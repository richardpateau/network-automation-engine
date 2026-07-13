from src.pipeline.resolver import resolve_pipeline


def run_pipeline(
        pipeline,
        context,
        session,
        device_state,
        device_result,
        log
):

    order = resolve_pipeline(pipeline)


    for feature in order:

        if feature not in context:
            continue


        compliance_function = (
            pipeline[feature]["function"]
        )


        try:

            compliance_function(
                session,
                context,
                device_state,
                device_result,
                log
            )


        except Exception as e:

            log.exception(
                f"Pipeline failed | {feature} | {e}"
            )

            device_result["critical_issues"].append(
                f"{feature} pipeline failure"
            )


    return device_result