import { ApolloClient, InMemoryCache, gql } from '@apollo/client';

const client = new ApolloClient({ uri: '/graphql', cache: new InMemoryCache() });
const GET_ITEM = gql`query GetItem($id: ID!) { item(id: $id) { name } }`;

export async function load() {
  const id = new URLSearchParams(window.location.search).get('id');
  const { data } = await client.query({ query: GET_ITEM, variables: { id } });
  return data;
}
