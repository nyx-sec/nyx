from step_b import step_b


def step_a(x):
    # Force a real cross-file call so pass-1 cannot resolve the callee
    # summary; the sink-reaching fact only emerges after the SCC fixed
    # point propagates step_b's refined summary backwards.
    step_b(x)
    return x
