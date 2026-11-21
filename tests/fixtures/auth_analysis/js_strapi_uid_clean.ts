// A Strapi `uid` selects a content type (`api::article.article`).  Helpers
// that pass it to the model registry or the query builder are not looking up
// a row by id.  Pinned in `auth_analysis_tests`.
export const getDeepPopulate = (uid: string, opts: any = {}) => {
  const model = strapi.getModel(uid);
  const meta = strapi.db.metadata.get(uid);
  return Object.keys(model.attributes).length + meta.columns.length;
};

export const createEntityManager = (db: any) => {
  return {
    async findOne(uid, params) {
      const states = await db.lifecycles.run("beforeFindOne", uid, { params });
      const result = await this.createQueryBuilder(uid).init(params).first().execute();
      return result;
    },
  };
};
