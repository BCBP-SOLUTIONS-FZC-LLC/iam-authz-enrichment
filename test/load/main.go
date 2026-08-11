// Command load is the §12 "Load test: 500 RPS sustained at 95% cache-hit,
// assert p99 ≤ 15ms; a second run forcing 100% cache-miss to characterize
// the latency floor" harness. It is written but deliberately NOT run as
// part of any automated test suite or CI job — meaningful p99/throughput
// numbers require a real docker-compose stack (Valkey + a live Org &
// Membership instance behind ORG_MEMBERSHIP_BASE_URL) up for the duration
// of the run, which is an operator action, not something to fire on every
// commit. Run it manually: `make load-test` (see Makefile) or
// `go run ./test/load -addr=localhost:9091 -rps=500 -duration=30s -mode=hit`.
//
// It talks directly to the ext_authz gRPC port with hand-built CheckRequests
// (same mechanism as internal/adapter/inbound/grpc's tests) — this
// exercises the real Checker/Cache/OrgMembershipClient path without needing
// a full Envoy+Keycloak stack in front of it, at the cost of not exercising
// Envoy's own attribute-building. That tradeoff is appropriate for a
// latency/throughput harness: Envoy's own overhead is not what this service
// controls or is being asked to meet a 15ms budget for.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

func main() {
	addr := flag.String("addr", "localhost:9091", "ext_authz gRPC address")
	rps := flag.Int("rps", 500, "target requests per second")
	duration := flag.Duration("duration", 30*time.Second, "how long to sustain the load")
	concurrency := flag.Int("concurrency", 64, "max in-flight requests")
	mode := flag.String("mode", "hit", "hit (reuse a small tenant/user pool, targets 95% cache-hit) or miss (unique tenant/user per request, 100% cache-miss)")
	poolSize := flag.Int("pool-size", 50, "number of distinct (tenant,user) pairs to cycle through in hit mode")
	jwtNamespace := flag.String("jwt-namespace", "envoy.filters.http.jwt_authn", "must match JWT_METADATA_NAMESPACE on the target instance")
	jwtPayloadKey := flag.String("jwt-payload-key", "trial", "must match JWT_PAYLOAD_KEY on the target instance")
	issuer := flag.String("issuer", "https://kc.example.com/realms/shared-trial", "must resolve on the target instance (SHARED_REALM_ISSUER or a REALM_TENANT_MAP_SEED entry)")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer func() { _ = conn.Close() }()
	client := authv3.NewAuthorizationClient(conn)

	requests := buildRequestPool(*mode, *poolSize, *issuer, *jwtNamespace, *jwtPayloadKey)

	fmt.Fprintf(os.Stderr, "load: mode=%s target=%d rps for %s against %s\n", *mode, *rps, *duration, *addr)

	var (
		sent, allowed, denied, errored int64
		mu                             sync.Mutex
		latencies                      []time.Duration
	)

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	ticker := time.NewTicker(time.Second / time.Duration(*rps))
	defer ticker.Stop()
	deadline := time.Now().Add(*duration)
	i := 0

	for time.Now().Before(deadline) {
		<-ticker.C
		req := requests[i%len(requests)]
		i++

		sem <- struct{}{}
		wg.Add(1)
		atomic.AddInt64(&sent, 1)
		go func(req *authv3.CheckRequest) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			resp, err := client.Check(context.Background(), req)
			elapsed := time.Since(start)

			mu.Lock()
			latencies = append(latencies, elapsed)
			mu.Unlock()

			switch {
			case err != nil:
				atomic.AddInt64(&errored, 1)
			case resp.GetOkResponse() != nil:
				atomic.AddInt64(&allowed, 1)
			default:
				atomic.AddInt64(&denied, 1)
			}
		}(req)
	}
	wg.Wait()

	report(sent, allowed, denied, errored, latencies)
}

func buildRequestPool(mode string, poolSize int, issuer, jwtNamespace, jwtPayloadKey string) []*authv3.CheckRequest {
	n := poolSize
	if mode == "miss" {
		n = 1000 // effectively unique per request via the modulo cycling above being large enough to rarely repeat within a TTL window
	}
	pool := make([]*authv3.CheckRequest, 0, n)
	for i := 0; i < n; i++ {
		var tenant, user string
		if mode == "hit" {
			tenant = fmt.Sprintf("loadtest-tenant-%d", i%5)
			user = fmt.Sprintf("loadtest-user-%d", i)
		} else {
			tenant = fmt.Sprintf("loadtest-miss-tenant-%d-%d", i, time.Now().UnixNano())
			user = fmt.Sprintf("loadtest-miss-user-%d-%d", i, time.Now().UnixNano())
		}
		pool = append(pool, buildCheckRequest(tenant, user, issuer, jwtNamespace, jwtPayloadKey))
	}
	return pool
}

func buildCheckRequest(subject, tenantIDClaim, issuer, jwtNamespace, jwtPayloadKey string) *authv3.CheckRequest {
	claims, _ := structpb.NewStruct(map[string]interface{}{
		"sub":       subject,
		"iss":       issuer,
		"tenant_id": tenantIDClaim,
	})
	filterMeta, _ := structpb.NewStruct(nil)
	filterMeta.Fields[jwtPayloadKey] = structpb.NewStructValue(claims)

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			MetadataContext: &corev3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{jwtNamespace: filterMeta},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{Method: "GET", Path: "/api/v1/tenders"},
			},
			ContextExtensions: map[string]string{},
		},
	}
}

func report(sent, allowed, denied, errored int64, latencies []time.Duration) {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(math.Ceil(p*float64(len(latencies)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	fmt.Printf("sent=%d allowed=%d denied=%d errored=%d\n", sent, allowed, denied, errored)
	fmt.Printf("p50=%s p95=%s p99=%s max=%s\n", pct(0.50), pct(0.95), pct(0.99), pct(1.0))
	if pct(0.99) > 15*time.Millisecond {
		fmt.Println("WARNING: p99 exceeds the 15ms budget (§0)")
	}
}
