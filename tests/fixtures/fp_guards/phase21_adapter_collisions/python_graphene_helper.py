import graphene


class Query(graphene.ObjectType):
    user = graphene.String()

    def resolve_user(self, info, id):
        return id


def normalize_id(raw):
    return str(raw)
