import React, { useState } from 'react';

// A pages-router file mixes a server data loader with a component.  The hook
// in the component says nothing about the loader, which reads a row by a
// client chosen id.
export async function getServerSideProps({ params }) {
  const post = await Post.findByPk(params.id);
  return { props: { post } };
}

export default function Page({ post }) {
  const [open] = useState(false);
  return <div>{open ? post.title : null}</div>;
}
