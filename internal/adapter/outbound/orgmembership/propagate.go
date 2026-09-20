package orgmembership

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

func propagateTraceparent(ctx context.Context, req *http.Request) {
	if req == nil {
		return
	}
	// Identical to gincommon.PropagateHeaders' inject step, usable from
	// outbound clients that only have context.Context rather than
	// *gin.Context (this service's I-8/I-12/I-14 calls originate from the
	// gRPC ext_authz path, not a Gin handler). Relies on the global
	// TextMapPropagator gincommon.InitTracingFromEnv /
	// ObservabilityMiddlewares install (TraceContext, plus Baggage when
	// enabled) — do not add a local TraceContext fallback; that would
	// bypass gincommon's propagator when tracing is not yet initialized.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
}
