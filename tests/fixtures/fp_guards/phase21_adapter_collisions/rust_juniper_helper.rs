use juniper::graphql_object;

pub struct Query;

#[graphql_object]
impl Query {
    fn user(&self, id: String) -> String {
        id
    }
}

pub fn normalize_id(id: &str) -> String {
    id.to_string()
}
