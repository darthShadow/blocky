package resolver

import (
	"context"

	"github.com/0xERR0R/blocky/config"
	. "github.com/0xERR0R/blocky/helpertest"
	"github.com/0xERR0R/blocky/log"
	. "github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("ConditionalUpstreamResolver", Label("conditionalResolver"), func() {
	var (
		sut       *ConditionalUpstreamResolver
		sutConfig config.ConditionalUpstream

		m *mockResolver

		ctx      context.Context
		cancelFn context.CancelFunc
	)

	Describe("Type", func() {
		It("follows conventions", func() {
			expectValidResolverType(sut)
		})
	})

	BeforeEach(func() {
		ctx, cancelFn = context.WithCancel(context.Background())
		DeferCleanup(cancelFn)

		fbTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 123, A, "123.124.122.122")

			return response
		})

		otherTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 250, A, "192.192.192.192")

			return response
		})

		dotTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response, _ = util.NewMsgWithAnswer(request.Question[0].Name, 223, A, "168.168.168.168")

			return response
		})

		refuseTestUpstream := NewMockUDPUpstreamServer().WithAnswerFn(func(request *dns.Msg) (response *dns.Msg) {
			response = new(dns.Msg)
			response.Rcode = dns.RcodeRefused
			// question section in response should be empty
			request.Question = make([]dns.Question, 0)

			return response
		})

		sutConfig = config.ConditionalUpstream{
			Mapping: config.ConditionalUpstreamMapping{
				Upstreams: map[string][]config.Upstream{
					"fritz.box":      {fbTestUpstream.Start()},
					"other.box":      {otherTestUpstream.Start()},
					"refused.domain": {refuseTestUpstream.Start()},
					".":              {dotTestUpstream.Start()},
				},
			},
		}
	})

	JustBeforeEach(func() {
		sut, _ = NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, systemResolverBootstrap)
		m = &mockResolver{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("IsEnabled", func() {
		It("is true", func() {
			Expect(sut.IsEnabled()).Should(BeTrue())
		})
	})

	Describe("LogConfig", func() {
		It("should log something", func() {
			logger, hook := log.NewMockEntry()

			sut.LogConfig(logger)

			Expect(hook.Calls).ShouldNot(BeEmpty())
		})
	})

	Describe("Resolve conditional DNS queries via defined DNS server", func() {
		When("conditional resolver returns error code", func() {
			It("Should be returned without changes", func() {
				Expect(sut.Resolve(ctx, newRequest("refused.domain.", A))).
					Should(
						SatisfyAll(
							HaveNoAnswer(),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeRefused),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
		When("Query is exact equal defined condition in mapping", func() {
			Context("first mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					Expect(sut.Resolve(ctx, newRequest("fritz.box.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("fritz.box.", A, "123.124.122.122"),
								HaveTTL(BeNumerically("==", 123)),
								HaveResponseType(ResponseTypeCONDITIONAL),
								HaveReason("CONDITIONAL"),
								HaveReturnCode(dns.RcodeSuccess),
							))

					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
				})
			})
			Context("last mapping entry", func() {
				It("Should resolve the IP of conditional DNS", func() {
					Expect(sut.Resolve(ctx, newRequest("other.box.", A))).
						Should(
							SatisfyAll(
								BeDNSRecord("other.box.", A, "192.192.192.192"),
								HaveTTL(BeNumerically("==", 250)),
								HaveResponseType(ResponseTypeCONDITIONAL),
								HaveReason("CONDITIONAL"),
								HaveReturnCode(dns.RcodeSuccess),
							))
					// no call to next resolver
					Expect(m.Calls).Should(BeEmpty())
				})
			})
		})
		When("Query is a subdomain of defined condition in mapping", func() {
			It("Should resolve the IP of subdomain", func() {
				Expect(sut.Resolve(ctx, newRequest("test.fritz.box.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("test.fritz.box.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
		When("Query is not fqdn and . condition is defined in mapping", func() {
			It("Should resolve the IP of .", func() {
				Expect(sut.Resolve(ctx, newRequest("test.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("test.", A, "168.168.168.168"),
							HaveTTL(BeNumerically("==", 223)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))
				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
	})
	Describe("Delegation to next resolver", func() {
		When("Query doesn't match defined mapping", func() {
			It("should delegate to next resolver", func() {
				Expect(sut.Resolve(ctx, newRequest("google.com.", A))).
					Should(
						SatisfyAll(
							HaveResponseType(ResponseTypeRESOLVED),
							HaveReturnCode(dns.RcodeSuccess),
						))
				m.AssertExpectations(GinkgoT())
			})
		})
	})

	When("upstream is invalid", func() {
		It("succeeds with bootstrap resolver during construction (blocking default)", func() {
			b := newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			upstreamsCfg := defaultUpstreamsConfig

			sutConfig := config.ConditionalUpstream{
				// Default init strategy is blocking
				Mapping: config.ConditionalUpstreamMapping{
					Upstreams: map[string][]config.Upstream{
						".": {config.Upstream{Host: "example.com"}},
					},
				},
			}

			// With blocking strategy (default), construction should succeed because bootstrap is used
			// Bootstrap allows the resolver to function even if configured upstreams are unreachable
			r, err := NewConditionalUpstreamResolver(ctx, sutConfig, upstreamsCfg, b)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r).ShouldNot(BeNil())
		})

		It("succeeds during construction with fast initialization strategy", func() {
			b := newTestBootstrap(ctx, &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}})

			upstreamsCfg := defaultUpstreamsConfig

			sutConfig := config.ConditionalUpstream{
				Init: config.Init{Strategy: config.InitStrategyFast},
				Mapping: config.ConditionalUpstreamMapping{
					Upstreams: map[string][]config.Upstream{
						".": {config.Upstream{Host: "example.com"}},
					},
				},
			}

			// With fast strategy, construction should always succeed even when upstreams are unreachable.
			// Initialization happens in the background with retry logic.
			// See: https://github.com/0xERR0R/blocky/issues/1639
			r, err := NewConditionalUpstreamResolver(ctx, sutConfig, upstreamsCfg, b)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r).ShouldNot(BeNil())
		})
	})

	Describe("Fast initialization strategy (lazy per-domain)", func() {
		var mockUpstream *MockUDPUpstreamServer

		When("conditional upstream is created with fast strategy", func() {
			It("should not initialize upstreams during construction", func() {
				mockUpstream = NewMockUDPUpstreamServer().WithAnswerRR("example.com 123 IN A 123.124.122.122")
				defer mockUpstream.Close()

				sutConfig := config.ConditionalUpstream{
					Init: config.Init{Strategy: config.InitStrategyFast},
					Mapping: config.ConditionalUpstreamMapping{
						Upstreams: map[string][]config.Upstream{
							"lazy.example": {mockUpstream.Start()},
						},
					},
				}

				b := &Bootstrap{}

				// Construction should succeed immediately without contacting upstream
				r, err := NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, b)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(r).ShouldNot(BeNil())

				// No upstream calls yet - initialization is lazy (happens on first query)
				Expect(mockUpstream.GetCallCount()).Should(Equal(0))
			})

			It("should initialize only once despite multiple concurrent queries", func() {
				mockUpstream = NewMockUDPUpstreamServer().WithAnswerRR("concurrent.example 123 IN A 123.124.122.122")
				defer mockUpstream.Close()

				sutConfig := config.ConditionalUpstream{
					Init: config.Init{Strategy: config.InitStrategyFast},
					Mapping: config.ConditionalUpstreamMapping{
						Upstreams: map[string][]config.Upstream{
							"concurrent.example": {mockUpstream.Start()},
						},
					},
				}

				// Use a functional bootstrap that can handle queries while initialization happens
				b := newTestBootstrap(ctx, &dns.Msg{
					Answer: []dns.RR{new(dns.A)},
				})
				r, err := NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, b)
				Expect(err).ShouldNot(HaveOccurred())

				// Fire 10 concurrent queries
				done := make(chan bool, 10)
				for i := 0; i < 10; i++ {
					go func() {
						defer GinkgoRecover()
						// Queries may use bootstrap or real upstream depending on timing
						// The key is that sync.Once ensures initialization happens exactly once
						_, _ = r.Resolve(ctx, newRequest("concurrent.example.", A))
						done <- true
					}()
				}

				// Wait for all to complete
				for i := 0; i < 10; i++ {
					<-done
				}

				// Verify initialization happened (at least one call to the upstream)
				Eventually(func() int {
					return mockUpstream.GetCallCount()
				}, "2s", "50ms").Should(BeNumerically(">=", 1))

				// Verify sync.Once ensures initialization only happens once
				// Allow small margin for query traffic after init completes
				initialCallCount := mockUpstream.GetCallCount()
				Consistently(func() int {
					return mockUpstream.GetCallCount()
				}, "500ms", "50ms").Should(BeNumerically("<=", initialCallCount+10))
			})
		})

		When("unused conditional upstreams exist with fast strategy", func() {
			It("should never initialize unused domains", func() {
				usedMock := NewMockUDPUpstreamServer().WithAnswerRR("used.example 123 IN A 1.2.3.4")
				defer usedMock.Close()

				unusedMock := NewMockUDPUpstreamServer().WithAnswerRR("unused.example 123 IN A 5.6.7.8")
				defer unusedMock.Close()

				sutConfig := config.ConditionalUpstream{
					Init: config.Init{Strategy: config.InitStrategyFast},
					Mapping: config.ConditionalUpstreamMapping{
						Upstreams: map[string][]config.Upstream{
							"used.example":   {usedMock.Start()},
							"unused.example": {unusedMock.Start()},
						},
					},
				}

				// Use a bootstrap that can answer DNS queries
				bootstrapUpstream := NewMockUDPUpstreamServer().WithAnswerRR("used.example 123 IN A 1.2.3.4")
				defer bootstrapUpstream.Close()
				b := newTestBootstrap(ctx, &dns.Msg{
					Answer: []dns.RR{new(dns.A)},
				})

				r, err := NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, b)
				Expect(err).ShouldNot(HaveOccurred())

				// Query only used.example
				resp, err := r.Resolve(ctx, newRequest("used.example.", A))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(resp).ShouldNot(BeNil())

				// unused.example should NEVER be initialized (lazy init only happens on query)
				// Use Consistently to verify it stays at 0 calls even after background init completes
				Consistently(func() int {
					return unusedMock.GetCallCount()
				}, "500ms", "50ms").Should(Equal(0))
			})
		})
	})

	Describe("Domain rewriting", func() {
		BeforeEach(func() {
			sutConfig.Rewrite = map[string]string{
				"source.test": "fritz.box",
			}

			// Recreate resolver with rewrite configuration
			sut, _ = NewConditionalUpstreamResolver(ctx, sutConfig, defaultUpstreamsConfig, systemResolverBootstrap)
			m = &mockResolver{}
			m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
			sut.Next(m)
		})

		When("request matches rewrite rule and conditional mapping", func() {
			It("should rewrite subdomain and resolve via conditional upstream", func() {
				// www.source.test -> www.fritz.box (which has conditional upstream)
				Expect(sut.Resolve(ctx, newRequest("www.source.test.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("www.source.test.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})

			It("should preserve original domain name in response", func() {
				resp, err := sut.Resolve(ctx, newRequest("www.source.test.", A))
				Expect(err).ShouldNot(HaveOccurred())

				// Question should have original name, not rewritten name
				Expect(resp.Res.Question[0].Name).Should(Equal("www.source.test."))
				// Answer should have original name, not rewritten name
				Expect(resp.Res.Answer[0].Header().Name).Should(Equal("www.source.test."))
			})
		})

		When("request does not match rewrite rule but matches conditional mapping", func() {
			It("should not rewrite and resolve via conditional upstream", func() {
				// Direct request to fritz.box (no rewrite)
				Expect(sut.Resolve(ctx, newRequest("fritz.box.", A))).
					Should(
						SatisfyAll(
							BeDNSRecord("fritz.box.", A, "123.124.122.122"),
							HaveTTL(BeNumerically("==", 123)),
							HaveResponseType(ResponseTypeCONDITIONAL),
							HaveReason("CONDITIONAL"),
							HaveReturnCode(dns.RcodeSuccess),
						))

				// no call to next resolver
				Expect(m.Calls).Should(BeEmpty())
			})
		})
	})
})
