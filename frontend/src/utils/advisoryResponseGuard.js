// An AI response may only be shown for the exact tool/evidence context that requested it.
export function createAdvisoryResponseGuard() {
  let context = null;
  let generation = 0;
  return {
    activate(nextContext) {
      if (context !== nextContext) {
        context = nextContext;
        generation += 1;
      }
    },
    begin(requestContext) {
      if (context !== requestContext) return null;
      generation += 1;
      return { context: requestContext, generation };
    },
    accepts(request, currentContext) {
      return Boolean(request
        && request.context === context
        && currentContext === context
        && request.generation === generation);
    },
    invalidate() {
      generation += 1;
    },
  };
}
