package resolver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	// Retry backoff configuration for conditional upstream initialization
	conditionalInitBaseBackoff = 5 * time.Second
	conditionalInitMaxBackoff  = 30 * time.Second
)

// retryableInit attempts to initialize an upstream group with exponential backoff retry logic.
// It runs in the background and updates the resolver's upstream list when initialization succeeds.
// This allows conditional upstreams to recover from transient failures without blocking startup.
func retryableInit(
	appCtx context.Context,
	r *ParallelBestResolver,
	cfg config.UpstreamGroup,
	bootstrap *Bootstrap,
	timeout time.Duration,
) {
	backoff := conditionalInitBaseBackoff

	attempt := 0

	for {
		attempt++

		// Use background context (independent of query cancellation)
		initCtx, cancel := context.WithTimeout(context.Background(), timeout)

		resolvers, err := createGroupResolvers(initCtx, cfg, bootstrap)
		cancel()

		if err == nil {
			// Success! Atomically swap in real resolvers
			r.setResolvers(resolvers)
			log.PrefixedLog("conditional_upstream_resolver").
				Infof("initialization successful for '%s' after %d attempt(s)", cfg.Name, attempt)
			return
		}

		log.PrefixedLog("conditional_upstream_resolver").
			WithError(err).
			Warnf("initialization failed for '%s' (attempt %d), retrying in %s", cfg.Name, attempt, backoff)

		// Exponential backoff with application context check
		select {
		case <-time.After(backoff):
			backoff = backoff * 2
			if backoff > conditionalInitMaxBackoff {
				backoff = conditionalInitMaxBackoff
			}
		case <-appCtx.Done():
			log.PrefixedLog("conditional_upstream_resolver").
				Infof("initialization cancelled for '%s': context cancelled", cfg.Name)
			return
		}
	}
}

// lazyConditionalResolver wraps a resolver with lazy initialization on first query.
// This ensures that unused conditional domains never waste resources on initialization.
//
// IMPORTANT: Until initialization succeeds, queries use the bootstrap resolver. This means
// the first queries to a conditional domain may receive responses from the bootstrap resolver
// (typically the default upstream) instead of the configured conditional upstream. Once
// background initialization completes successfully, all subsequent queries will use the
// configured upstream. This is a deliberate trade-off to avoid blocking service startup.
type lazyConditionalResolver struct {
	appCtx    context.Context
	cfg       config.UpstreamGroup
	bootstrap *Bootstrap
	timeout   time.Duration

	initOnce sync.Once
	resolver atomic.Pointer[ParallelBestResolver]
}

func newLazyConditionalResolver(
	ctx context.Context, cfg config.UpstreamGroup, bootstrap *Bootstrap,
) *lazyConditionalResolver {
	timeout := cfg.Timeout.ToDuration()
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	return &lazyConditionalResolver{
		appCtx:    ctx,
		cfg:       cfg,
		bootstrap: bootstrap,
		timeout:   timeout,
	}
}

func (l *lazyConditionalResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	// Lazy init on first query to this domain
	l.initOnce.Do(func() {
		pbr := newParallelBestResolver(l.cfg, []Resolver{l.bootstrap})
		l.resolver.Store(pbr)

		// Launch background retry in goroutine with application context for proper shutdown
		go retryableInit(l.appCtx, pbr, l.cfg, l.bootstrap, l.timeout)
	})

	return l.resolver.Load().Resolve(ctx, request)
}

func (l *lazyConditionalResolver) String() string {
	if r := l.resolver.Load(); r != nil {
		return r.String()
	}
	return fmt.Sprintf("lazy conditional resolver for %s (not initialized)", l.cfg.Name)
}

func (l *lazyConditionalResolver) Type() string {
	if r := l.resolver.Load(); r != nil {
		return r.Type()
	}
	return "lazy_conditional"
}

func (l *lazyConditionalResolver) IsEnabled() bool {
	return true
}

func (l *lazyConditionalResolver) LogConfig(logger *logrus.Entry) {
	if r := l.resolver.Load(); r != nil {
		r.LogConfig(logger)
	} else {
		logger.Infof("lazy conditional resolver for %s (not yet initialized)", l.cfg.Name)
	}
}

// ConditionalUpstreamResolver delegates DNS question to other DNS resolver dependent on domain name in question
type ConditionalUpstreamResolver struct {
	configurable[*config.ConditionalUpstream]
	NextResolver
	typed

	mapping map[string]Resolver
}

// NewConditionalUpstreamResolver returns new resolver instance
func NewConditionalUpstreamResolver(
	ctx context.Context, cfg config.ConditionalUpstream, upstreamsCfg config.Upstreams, bootstrap *Bootstrap,
) (*ConditionalUpstreamResolver, error) {
	m := make(map[string]Resolver, len(cfg.Mapping.Upstreams))

	for domain, upstreams := range cfg.Mapping.Upstreams {
		name := fmt.Sprintf("<conditional in %s>", domain)
		groupCfg := config.NewUpstreamGroup(name, upstreamsCfg, upstreams)

		// Override with conditional-specific init strategy
		groupCfg.Init = cfg.Init

		var r Resolver
		var err error

		if cfg.Init.Strategy == config.InitStrategyFast {
			// Fast strategy: lazy initialization on first query to this domain
			// This avoids blocking service startup while ensuring unused domains
			// never waste resources on initialization.
			// Benefits:
			// - Non-blocking startup
			// - Background context for initialization (independent of query timeout)
			// - Retry logic with exponential backoff
			// - Unused domains never initialized
			// See: https://github.com/0xERR0R/blocky/issues/1639
			r = newLazyConditionalResolver(ctx, groupCfg, bootstrap)
		} else {
			// Blocking/FailOnError strategy: synchronous initialization
			// Ensures conditional upstreams are ready immediately but may block startup
			// if upstreams are unreachable
			r, err = NewParallelBestResolver(ctx, groupCfg, bootstrap)
			if err != nil {
				return nil, fmt.Errorf("initialization failed for conditional upstream domain '%s': %w", domain, err)
			}
		}

		m[strings.ToLower(domain)] = r
	}

	return &ConditionalUpstreamResolver{
		configurable: withConfig(&cfg),
		typed:        withType("conditional_upstream"),

		mapping: m,
	}, nil
}

func (r *ConditionalUpstreamResolver) processRequest(
	ctx context.Context, request *model.Request,
) (bool, *model.Response, error) {
	domainFromQuestion := util.ExtractDomain(request.Req.Question[0])
	domain := domainFromQuestion

	if strings.Contains(domainFromQuestion, ".") {
		// try with domain with and without sub-domains
		for len(domain) > 0 {
			if resolver, found := r.mapping[domain]; found {
				resp, err := r.internalResolve(ctx, resolver, domainFromQuestion, domain, request)

				return true, resp, err
			}

			if i := strings.Index(domain, "."); i >= 0 {
				domain = domain[i+1:]
			} else {
				break
			}
		}
	} else if resolver, found := r.mapping["."]; found {
		resp, err := r.internalResolve(ctx, resolver, domainFromQuestion, domain, request)

		return true, resp, err
	}

	return false, nil, nil
}

// Resolve uses the conditional resolver to resolve the query
func (r *ConditionalUpstreamResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	// Apply domain rewrites if configured
	original := request.Req
	rewritten, originalNames := rewriteRequest(logger, original, r.cfg.Rewrite)
	if rewritten != nil {
		request.Req = rewritten
	}

	var response *model.Response
	var err error

	resolved := false
	if len(r.mapping) > 0 {
		resolved, response, err = r.processRequest(ctx, request)
		if err != nil {
			return nil, err
		}
	}

	if !resolved {
		logger.WithField("next_resolver", Name(r.next)).Trace("go to next resolver")
		response, err = r.next.Resolve(ctx, request)
		if err != nil {
			return nil, err
		}
	}

	// Revert the request
	request.Req = original

	// Revert rewrites in the response
	if rewritten != nil && response != NoResponse && response != nil && response.Res != nil {
		revertRewritesInResponse(response.Res, originalNames)
	}

	return response, nil
}

func (r *ConditionalUpstreamResolver) internalResolve(ctx context.Context, reso Resolver, doFQ, do string,
	req *model.Request,
) (*model.Response, error) {
	// internal request resolution
	ctx, logger := r.log(ctx)

	req.Req.Question[0].Name = dns.Fqdn(doFQ)
	response, err := reso.Resolve(ctx, req)

	if err == nil {
		response.Reason = "CONDITIONAL"
		response.RType = model.ResponseTypeCONDITIONAL

		if len(response.Res.Question) > 0 {
			response.Res.Question[0].Name = req.Req.Question[0].Name
		}
	} else {
		return nil, fmt.Errorf("resolution failed for conditional upstream domain '%s': %w", do, err)
	}

	var answer string
	if response != nil {
		answer = util.AnswerToString(response.Res.Answer)
	}

	logger.WithFields(logrus.Fields{
		"answer":   answer,
		"domain":   util.Obfuscate(do),
		"upstream": reso,
	}).Debugf("received response from conditional upstream")

	return response, nil
}
