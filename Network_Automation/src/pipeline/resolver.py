def resolve_pipeline(pipeline):

    ordered = []
    visited = set()
    visiting = set()

    def visit(feature):

        if feature in visiting:
            raise Exception(
                f"Circular dependency detected: {feature}"
            )

        if feature in visited:
            return

        visiting.add(feature)

        for dep in pipeline[feature]["depends_on"]:
            visit(dep)

        visiting.remove(feature)

        visited.add(feature)

        ordered.append(feature)

    for feature in pipeline:
        visit(feature)

    return ordered