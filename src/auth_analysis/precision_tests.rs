//! End-to-end precision tests for the ownership rule.  Each case runs the
//! whole auth pass over an inline snippet.  A `fires` case pins recall for the
//! shape next to the suppressed one.

use super::test_support::ownership_lines;

mod go {
    use super::ownership_lines;

    fn go(src: &str) -> Vec<usize> {
        ownership_lines("go", src)
    }

    // --- request accessors are user input only on a request receiver ------

    #[test]
    fn cache_get_does_not_open_a_helper() {
        let src = r#"package store

func LoadRepo(cache *Cache, repos []Repo) {
	v := cache.Get("k")
	_ = v
	repo_model.GetRepositoryByID(repos[0].ID)
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn header_get_and_db_query_do_not_open_a_helper() {
        let src = r#"package store

func Sync(db *xorm.Engine, resp *http.Response, ids []int64) {
	etag := resp.Header.Get("ETag")
	rows, _ := db.Query("select 1")
	_, _ = etag, rows
	store.DeleteByID(ids[0])
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn request_param_on_a_gin_context_still_opens_the_function() {
        let src = r#"package store

func Remove(c *gin.Context) {
	id := c.Param("id")
	store.DB.DeletePost(id)
}
"#;
        assert_eq!(go(src), vec![5]);
    }

    #[test]
    fn form_value_on_a_request_alias_still_opens_the_function() {
        let src = r#"package store

func Remove(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("id")
	store.DB.DeletePost(id)
}
"#;
        assert_eq!(go(src), vec![6]);
    }

    #[test]
    fn request_param_inside_a_route_closure_counts_for_the_closure() {
        let src = r#"package main

func main() {
	r.GET("/posts/:id", func(c *gin.Context) {
		id := c.Param("id")
		store.DB.DeletePost(id)
	})
}
"#;
        assert_eq!(go(src), vec![6]);
    }

    // --- request-context scope and actor chains ---------------------------

    #[test]
    fn context_repo_scope_id_is_not_a_foreign_id() {
        let src = r#"package repo

func GetReleaseByTag(ctx *context.APIContext) {
	tag := ctx.PathParam("tag")
	release, err := repo_model.GetRelease(ctx, ctx.Repo.Repository.ID, tag)
	_, _ = release, err
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn context_doer_id_is_the_actor() {
        let src = r#"package security

func EnrollTwoFactor(ctx *context.Context) {
	name := ctx.PathParam("name")
	t, err := auth.GetTwoFactorByUID(ctx, ctx.Doer.ID)
	_, _, _ = t, err, name
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn scope_alias_of_a_context_entity_is_a_scope() {
        let src = r#"package packages

func Delete(ctx *context.Context) {
	name := ctx.PathParam("name")
	owner := ctx.Package.Owner
	pv, err := packages_model.GetVersionByNameAndVersion(ctx, owner.ID, name, "1")
	_, _ = pv, err
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn co_passed_scope_id_makes_the_lookup_tenant_scoped() {
        let scoped_param = r#"package repo

func getLabel(ctx *context.APIContext, repo *repo_model.Repository) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelInRepoByID(ctx, repo.ID, labelID)
	_, _ = l, err
}
"#;
        assert!(go(scoped_param).is_empty(), "{:?}", go(scoped_param));
        let scoped_ctx = r#"package repo

func GetLabel(ctx *context.APIContext) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelInRepoByID(ctx, ctx.Repo.Repository.ID, labelID)
	_, _ = l, err
}
"#;
        assert!(go(scoped_ctx).is_empty(), "{:?}", go(scoped_ctx));
    }

    #[test]
    fn unscoped_lookup_by_request_id_still_fires() {
        let src = r#"package repo

func GetLabel(ctx *context.APIContext) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelByID(ctx, labelID)
	_, _ = l, err
}
"#;
        assert_eq!(go(src), vec![5]);
    }

    #[test]
    fn request_payload_chain_is_not_a_scope() {
        let src = r#"package repo

func GetLabel(ctx *context.APIContext) {
	_ = ctx.Req.FormValue("id")
	l, err := issues_model.GetLabelByID(ctx, ctx.Req.Form.ID)
	_, _ = l, err
}
"#;
        assert_eq!(go(src), vec![5]);
    }

    // --- in-memory values and request data are not data-layer clients -----

    #[test]
    fn atomic_field_receiver_named_like_an_id_is_not_a_sink() {
        let src = r#"package commands

type rootCommand struct {
	configVersionID atomic.Int32
}

func reload(r *rootCommand, req *http.Request) int32 {
	return r.configVersionID.Load()
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn local_set_is_not_a_sink() {
        let src = r#"package user

func GetPossibleUserByIDs(req *http.Request, ids []int64) {
	uniqueIDs := container.SetOf(ids...)
	uniqueIDs.Remove(0)
	seen := make(map[int64]bool)
	_ = seen
	vals := url.Values{}
	vals.Add("id", "1")
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn local_set_named_without_id_is_tracked_through_its_binding() {
        let src = r#"package user

func Prune(req *http.Request, userID int64) {
	members := container.SetOf(1, 2)
	members.Remove(userID)
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn stdlib_slice_helpers_are_not_sinks() {
        let src = r#"package user

func Prune(req *http.Request, userID int64, list []int64) {
	list = slices.Delete(list, 0, 1)
	_ = sort.Find(len(list), func(i int) int { return 0 })
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn header_and_form_accessors_are_not_sinks() {
        let src = r#"package cmd

func GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	vid := r.Form.Get(xhttp.VersionID)
	r.Header.Add(requestid.HeaderXRequestID, vid)
	w.Write([]byte(vid))
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn route_registration_is_not_a_lookup() {
        let src = r#"package web

func registerWebRoutes(m *web.Router, req *http.Request) {
	m.Get("/blob/{sha}", repo.DownloadByID)
	m.Delete("/blob/{sha}", func(ctx *context.Context) {})
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    // --- package-level names ----------------------------------------------

    #[test]
    fn imported_package_constants_are_not_subjects() {
        let src = r#"package cmd

import (
	"net/http"

	"example.com/cfgmgr"
	"example.com/common"
)

func LoadLDAP(req *http.Request) {
	uid := cfgmgr.Mgr.Get(req.Context(), common.LDAPUID)
	_ = uid
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn file_const_keys_are_not_subjects() {
        let src = r#"package cmd

const storageRESTDiskID = "diskID"

func Handler(w http.ResponseWriter, r *http.Request) {
	store.Lookup(r, storageRESTDiskID)
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn a_param_that_shadows_an_import_is_still_a_subject() {
        let src = r#"package harbor

import "example.com/event"

func Handle(req *http.Request, event *Event) {
	store.DB.DeleteEvent(event.ID)
}
"#;
        assert_eq!(go(src), vec![6]);
    }

    #[test]
    fn a_local_that_shadows_a_const_is_still_a_subject() {
        let src = r#"package cmd

const userID = "fixed"

func Handler(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("userID")
	store.DB.DeleteUser(userID)
}
"#;
        assert_eq!(go(src), vec![7]);
    }

    // --- named id types ---------------------------------------------------

    #[test]
    fn helper_params_with_named_id_types_are_not_user_input() {
        let src = r#"package endpoints

func removeEndpoint(tx dataservices.DataStoreTx, endpointID portainer.EndpointID) error {
	return tx.EndpointStore.DeleteEndpoint(endpointID)
}

func removeTargets(tx dataservices.DataStoreTx, ids ...TargetID) error {
	return tx.TargetStore.DeleteTargets(ids)
}

func removeMany(tx dataservices.DataStoreTx, ids []int64, byGroup map[int64]int64) error {
	return tx.EndpointStore.DeleteMany(ids, byGroup)
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn route_handler_keeps_named_id_params() {
        let src = r#"package main

func deleteEndpoint(c *gin.Context, endpointID portainer.EndpointID) {
	store.DB.DeleteEndpoint(endpointID)
}

func main() {
	r.DELETE("/endpoints/:id", deleteEndpoint)
}
"#;
        assert_eq!(go(src), vec![4]);
    }

    // --- fetch then authorize ---------------------------------------------

    #[test]
    fn fetch_then_authorize_exempts_the_fetch() {
        let src = r#"package repo

func DeleteIssue(ctx *context.Context) {
	id := ctx.PathParam("id")
	issue, err := issues_model.GetIssueByID(ctx, id)
	if err != nil {
		return
	}
	if !CheckOwnership(ctx, issue) {
		return
	}
	issues_model.DeleteIssue(ctx, issue.ID)
}
"#;
        assert!(go(src).is_empty(), "{:?}", go(src));
    }

    #[test]
    fn fetch_without_any_check_still_fires() {
        let src = r#"package repo

func DeleteIssue(ctx *context.Context) {
	id := ctx.PathParam("id")
	issue, err := issues_model.GetIssueByID(ctx, id)
	if err != nil {
		return
	}
	_ = issue
}
"#;
        assert_eq!(go(src), vec![5]);
    }
}

mod id_like_names {
    use super::ownership_lines;

    #[test]
    fn python_words_ending_in_id_are_not_ids() {
        let src = r#"
@app.route("/orders")
def orders(paid):
    return Order.query.filter_by(paid=paid).all()

@app.route("/devices")
def devices(android):
    return Device.query.filter_by(android=android).all()

@app.route("/submit")
def submit(valid):
    return Submission.create(valid=valid)
"#;
        assert!(
            ownership_lines("python", src).is_empty(),
            "{:?}",
            ownership_lines("python", src)
        );
    }

    #[test]
    fn python_real_ids_still_fire() {
        let src = r#"
@app.route("/orders/<order_id>")
def orders(order_id):
    return Order.query.filter_by(id=order_id).all()
"#;
        assert_eq!(ownership_lines("python", src), vec![4]);
    }
}

mod js {
    use super::ownership_lines;
    use crate::auth_analysis::test_support::findings_at;

    fn js(src: &str) -> Vec<usize> {
        ownership_lines("javascript", src)
    }

    fn ts(src: &str) -> Vec<usize> {
        ownership_lines("typescript", src)
    }

    fn tsx(src: &str) -> Vec<usize> {
        ownership_lines("tsx", src)
    }

    // --- browser code ------------------------------------------------------

    #[test]
    fn react_components_and_hooks_are_not_server_handlers() {
        let src = r#"
import { useTranslation } from "react-i18next";

export const FlowTitle = ({ id, providerId }) => {
  const { providers } = useAuthenticationProvider();
  const helpText = providers?.find((p) => p.id === providerId)?.description;
  return <span data-id={id}>{helpText}</span>;
};

export const UserToggle = ({ userId }) => {
  const { adminClient } = useAdminClient();
  const enable = async () => {
    await adminClient.users.update({ id: userId }, { enabled: true });
  };
  return <button onClick={enable}>Enable</button>;
};

export default function useSidebarLabel(documentId) {
  const { documents } = useStores();
  return documents.get(documentId);
}
"#;
        assert!(tsx(src).is_empty(), "{:?}", tsx(src));
    }

    #[test]
    fn use_client_directive_marks_the_whole_file() {
        let src = r#"'use client';
export async function deleteItem(itemId) {
  await store.items.delete(itemId);
}
"#;
        assert!(tsx(src).is_empty(), "{:?}", tsx(src));
    }

    #[test]
    fn async_server_component_stays_in_scope() {
        let src = r#"
import { prisma } from "@/lib/prisma";

export default async function InvoicePage({ params }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.invoiceId } });
  return <div>{invoice?.total}</div>;
}
"#;
        assert_eq!(tsx(src), vec![5]);
    }

    #[test]
    fn server_file_with_a_use_prefixed_helper_is_not_browser_code() {
        let src = r#"
const express = require('express');
async function useRemoval(noteId) {
  await prisma.note.delete({ where: { noteId } });
}
"#;
        assert_eq!(js(src), vec![4]);
    }

    // --- http client wrappers ---------------------------------------------

    #[test]
    fn http_client_calls_from_a_helper_are_not_data_ops() {
        let src = r#"
import axios from 'axios';

export async function deleteTodo(todoId) {
  await axios.delete(`/api/todos/${todoId}`);
}

export const updateTodo = async (id, data) => {
  return api.put(`/todos/${id}`, data);
};
"#;
        assert!(ts(src).is_empty(), "{:?}", ts(src));
    }

    #[test]
    fn http_client_call_inside_a_route_handler_still_counts() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.delete('/proxy/:id', async (req, res) => {
  await axios.delete(`https://upstream.example.com/items/${req.params.id}`);
  res.sendStatus(204);
});
"#;
        assert_eq!(js(src), vec![6]);
    }

    // --- shorthand and verbs ----------------------------------------------

    #[test]
    fn shorthand_where_id_is_a_subject() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.delete('/notes/:id', async (req, res) => {
  const { id } = req.params;
  await prisma.note.delete({ where: { id } });
});
"#;
        assert_eq!(js(src), vec![7]);
    }

    #[test]
    fn shorthand_self_actor_id_is_not_a_foreign_id() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.get('/me/notes', async (req, res) => {
  const userId = req.user.id;
  const notes = await prisma.note.findMany({ where: { userId } });
  res.json(notes);
});
"#;
        assert!(js(src).is_empty(), "{:?}", js(src));
    }

    #[test]
    fn sequelize_destroy_and_upsert_are_mutations() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.delete('/d/:docId', async (req, res) => {
  await Doc.destroy({ where: { id: req.params.docId } });
});

router.put('/f/:docId', async (req, res) => {
  await Doc.upsert({ id: req.params.docId });
});
"#;
        assert_eq!(js(src), vec![6, 10]);
    }

    // --- fetch then authorize ---------------------------------------------

    #[test]
    fn fetch_then_authorize_survives_later_writes_and_rebinding() {
        let src = r#"
async function updateDocument(id, user, title) {
  let document = await Document.findByPk(id);
  authorize(user, 'update', document);
  document = await documentUpdater(document, title);
  return document;
}

async function renameDocument(id, user, title) {
  const document = await Document.findByPk(id);
  authorize(user, 'update', document);
  document.title = title.trim();
  return document.save();
}

async function loadEither(id, user, archived) {
  if (archived) {
    const document = await Archive.findByPk(id);
    authorize(user, 'read', document);
    return document;
  } else {
    const document = await Document.findByPk(id);
    authorize(user, 'read', document);
    return document;
  }
}
"#;
        assert!(js(src).is_empty(), "{:?}", js(src));
    }

    #[test]
    fn fetch_then_authorize_covers_promise_all_and_ternary_bindings() {
        let src = r#"
async function loadBoth(id, groupId, user) {
  const [document, group] = await Promise.all([
    Document.findByPk(id),
    Group.findByPk(groupId),
  ]);
  authorize(user, 'read', document);
  authorize(user, 'read', group);
  return [document, group];
}

async function loadOrSelf(id, user) {
  const target = id ? await User.findByPk(id) : user;
  authorize(user, 'read', target);
  return target;
}
"#;
        assert!(js(src).is_empty(), "{:?}", js(src));
    }

    #[test]
    fn fetch_without_authorize_still_fires_after_field_write() {
        let src = r#"
async function readDocument(id) {
  const document = await Document.findByPk(id);
  document.viewed = true;
  return document;
}

async function readBoth(id, groupId) {
  const [document, group] = await Promise.all([
    Document.findByPk(id),
    Group.findByPk(groupId),
  ]);
  return [document, group];
}
"#;
        assert_eq!(js(src), vec![3, 10, 11]);
    }

    #[test]
    fn authorizing_one_promise_all_row_does_not_cover_the_other() {
        let src = r#"
async function loadBoth(id, groupId, user) {
  const [document, group] = await Promise.all([
    Document.findByPk(id),
    Group.findByPk(groupId),
  ]);
  authorize(user, 'read', document);
  return [document, group];
}
"#;
        assert_eq!(js(src), vec![5]);
    }

    // --- callbacks ---------------------------------------------------------

    #[test]
    fn array_predicates_are_not_reads() {
        let src = r#"
export function pick(providers, providerId, documents, documentId) {
  const p = providers.find((p) => p.id === providerId);
  const i = documents.findIndex((d) => d.id === documentId);
  return [p, i];
}
"#;
        assert!(ts(src).is_empty(), "{:?}", ts(src));
    }

    #[test]
    fn driver_callback_last_is_still_a_read() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.get('/notes/:id', (req, res) => {
  Note.findById(req.params.id, function (err, note) {
    res.json(note);
  });
});
"#;
        assert_eq!(js(src), vec![6]);
    }

    // --- actors ------------------------------------------------------------

    #[test]
    fn koa_state_auth_actor_and_own_team_are_self_scoped() {
        let src = r#"
import Router from "@koa/router";
const router = new Router();

router.post("integrations.create", async (ctx) => {
  const { user } = ctx.state.auth;
  await Integration.create({ userId: user.id, teamId: user.teamId });
  const team = await Team.findByPk(user.teamId);
  ctx.body = { team };
});

router.get("team.info", async (ctx) => {
  const user = ctx.state.user;
  const team = await Team.findByPk(user.teamId);
  ctx.body = { team };
});
"#;
        assert!(ts(src).is_empty(), "{:?}", ts(src));
    }

    #[test]
    fn koa_foreign_team_id_from_the_request_still_fires() {
        let src = r#"
import Router from "@koa/router";
const router = new Router();

router.post("team.info", async (ctx) => {
  const team = await Team.findByPk(ctx.input.body.teamId);
  ctx.body = { team };
});
"#;
        assert_eq!(ts(src), vec![6]);
    }

    #[test]
    fn session_user_id_is_self_scoped_for_reads_and_writes() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.get('/me', async (req, res) => {
  const me = await db.user.findFirst({ where: { id: req.session.userId } });
  res.json(me);
});

router.put('/me', async (req, res) => {
  await User.update({ name: req.body.name }, { where: { id: req.session.userId } });
  res.sendStatus(204);
});
"#;
        let all = findings_at("javascript", "h.js", src);
        assert!(
            all.iter()
                .all(|(rule, _)| !rule.contains("ownership") && !rule.contains("stale")),
            "{all:?}"
        );
    }

    #[test]
    fn foreign_session_carried_id_still_fires() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.get('/w', async (req, res) => {
  const w = await db.workspace.findFirst({ where: { id: req.session.workspaceId } });
  res.json(w);
});
"#;
        assert!(!js(src).is_empty());
    }

    // --- uid ---------------------------------------------------------------

    #[test]
    fn schema_uid_helper_is_not_a_row_lookup() {
        let src = r#"
export const getDeepPopulate = (uid, opts = {}) => {
  const model = strapi.getModel(uid);
  const meta = strapi.db.metadata.get(uid);
  return Object.keys(model.attributes).length + meta.columns.length;
};

export const createEntityManager = (db) => {
  return {
    async findOne(uid, params) {
      const states = await db.lifecycles.run("beforeFindOne", uid, { params });
      const result = await this.createQueryBuilder(uid).init(params).first().execute();
      return result;
    },
  };
};
"#;
        assert!(ts(src).is_empty(), "{:?}", ts(src));
    }

    #[test]
    fn route_uid_param_is_still_a_subject() {
        let src = r#"
import express from "express";
const app = express();

app.get("/users/:uid", async (req, res) => {
  const uid = req.params.uid;
  const doc = await db.users.findOne({ where: { uid } });
  res.json(doc);
});
"#;
        assert_eq!(ts(src), vec![7]);
    }

    // --- route-level middleware -------------------------------------------

    #[test]
    fn authorization_middleware_on_the_route_guards_the_handler() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.get('/docs/:id', checkOwnership, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});

router.put('/docs/:id', hasPermission('docs:write'), async (req, res) => {
  await Doc.updateOne({ _id: req.params.id }, req.body);
});
"#;
        assert!(js(src).is_empty(), "{:?}", js(src));
    }

    #[test]
    fn router_use_middleware_guards_later_routes_on_the_same_router() {
        let src = r#"
const express = require('express');
const router = express.Router();
const admin = express.Router();

admin.use(authorize('admin'));

admin.delete('/docs/:docId', async (req, res) => {
  await Doc.deleteOne({ _id: req.params.docId });
});

router.delete('/notes/:noteId', async (req, res) => {
  await Note.deleteOne({ _id: req.params.noteId });
});
"#;
        assert_eq!(js(src), vec![13]);
    }

    #[test]
    fn handler_registered_without_the_check_stays_unguarded() {
        let src = r#"
const express = require('express');
const router = express.Router();

async function removeDoc(req, res) {
  await Doc.deleteOne({ _id: req.params.docId });
}

router.delete('/guarded/docs/:docId', checkOwnership, removeDoc);
router.delete('/open/docs/:docId', removeDoc);
"#;
        assert_eq!(js(src), vec![6]);
    }

    #[test]
    fn login_only_middleware_does_not_suppress() {
        let src = r#"
const express = require('express');
const router = express.Router();

router.delete('/notes/:noteId', requireLogin, async (req, res) => {
  await Note.deleteOne({ _id: req.params.noteId });
});
"#;
        assert_eq!(js(src), vec![6]);
    }

    // --- controller recall -------------------------------------------------

    #[test]
    fn commonjs_exports_and_plain_class_methods_are_handlers() {
        let src = r#"
exports.remove = async (req, res) => {
  await Doc.deleteOne({ _id: req.params.docId });
};

module.exports.show = async function (req, res) {
  const doc = await Doc.findById(req.params.docId);
  res.json(doc);
};

module.exports = {
  async update(req, res) {
    await Doc.updateOne({ _id: req.params.docId }, req.body);
  },
};

class DocController {
  async archive(req, res) {
    await Doc.updateOne({ _id: req.params.docId }, { archived: true });
  }
}
"#;
        assert_eq!(js(src), vec![3, 7, 13, 19]);
    }

    #[test]
    fn decorated_classes_are_left_to_their_decorators() {
        let src = r#"
@Controller('docs')
export class DocsController {
  @Delete(':docId')
  async remove(@Param('docId') docId: string) {
    return this.docRepo.delete(docId);
  }
}
"#;
        assert!(ts(src).is_empty(), "{:?}", ts(src));
    }

    #[test]
    fn named_router_variables_register_routes() {
        let src = r#"
const express = require('express');
const userRouter = express.Router();

userRouter.delete('/users/:userId', checkOwnership, async (req, res) => {
  await User.deleteOne({ _id: req.params.userId });
});

userRouter.delete('/open/:userId', async (req, res) => {
  await User.deleteOne({ _id: req.params.userId });
});
"#;
        // Both are routes on a router named `userRouter`; the first runs
        // behind a route-level check and the second does not.
        assert_eq!(js(src), vec![10]);
    }
}

mod row_provenance {
    use super::ownership_lines;

    #[test]
    fn go_field_of_a_scoped_fetch_is_a_row_attribute() {
        let src = r#"package repo

func DeletePackageFile(ctx *context.Context) {
	owner := ctx.Package.Owner
	pv, err := packages.GetVersionByNameAndVersion(ctx, owner.ID, 1, ctx.PathParam("name"))
	if err != nil {
		return
	}
	pf, err := packages.GetFileForVersionByName(ctx, pv.ID, ctx.PathParam("filename"))
	_, _ = pf, err
}
"#;
        assert!(ownership_lines("go", src).is_empty());
    }

    #[test]
    fn go_range_variable_over_scoped_rows_is_a_row_attribute() {
        let src = r#"package repo

func Sweep(ctx *context.Context) {
	tasks, err := auth.FindTasks(ctx, ctx.Repo.Repository.ID)
	_ = err
	for _, t := range tasks {
		a, _ := auth.GetUserByID(ctx, t.UserID)
		_ = a
	}
}
"#;
        assert!(ownership_lines("go", src).is_empty());
    }

    #[test]
    fn go_field_of_a_name_only_fetch_still_fires() {
        let src = r#"package repo

func DeleteByName(ctx *context.Context) {
	r, err := repo.GetRepoByName(ctx, ctx.PathParam("name"))
	if err != nil {
		return
	}
	repo.DeleteRepoByID(ctx, r.ID)
}
"#;
        assert_eq!(ownership_lines("go", src), vec![8]);
    }

    #[test]
    fn go_range_over_name_only_fetch_still_fires() {
        let src = r#"package repo

func Sweep(ctx *context.Context) {
	tasks, err := auth.FindTasks(ctx, ctx.PathParam("repo"))
	_ = err
	for _, t := range tasks {
		auth.DeleteTaskByID(ctx, t.ID)
	}
}
"#;
        assert_eq!(ownership_lines("go", src), vec![7]);
    }

    #[test]
    fn js_fk_of_an_id_keyed_row_is_exempt_but_the_first_fetch_fires() {
        let src = r#"router.get("/documents/:id", async (req, res) => {
  const doc = await Document.findByPk(req.params.id);
  const parent = await Document.findByPk(doc.parentDocumentId);
  res.json({ doc, parent });
});
"#;
        assert_eq!(ownership_lines("javascript", src), vec![2]);
    }

    #[test]
    fn js_entity_param_fk_is_exempt_outside_a_request() {
        let src = r#"async function moveDocument({ document, user }) {
  return Collection.findByPk(document.collectionId);
}
"#;
        assert!(ownership_lines("javascript", src).is_empty());
    }

    #[test]
    fn js_raw_id_param_still_fires() {
        let src = r#"async function moveDocument({ collectionId, user }) {
  return Collection.findByPk(collectionId);
}
"#;
        assert_eq!(ownership_lines("javascript", src), vec![2]);
    }

    #[test]
    fn js_id_converted_from_a_request_value_is_not_a_row() {
        let src = r#"router.delete("/docs/:id", async (req, res) => {
  const docId = parseInt(req.params.id);
  await Document.destroy({ where: { id: docId } });
});
"#;
        assert_eq!(ownership_lines("javascript", src), vec![3]);
    }

    #[test]
    fn js_insert_minted_id_and_rows_loop_are_exempt() {
        let src = r#"const em = (db) => ({
  async create(uid, params) {
    const res = await db.createQueryBuilder(uid).insert(params.data).execute();
    const id = isRecord(res[0]) ? res[0].id : res[0];
    return this.findOne(uid, { where: { id } });
  },
  async remove(uid, params) {
    const rows = await db.query(uid).findMany(params.where);
    return Promise.all(rows.map((row) => entries.delete(row.id, {})));
  },
});
"#;
        assert!(ownership_lines("javascript", src).is_empty());
    }

    #[test]
    fn js_scope_segments_named_create_or_insert_do_not_mint() {
        let src = r#"app.post('/a', async (req, res) => {
  const d = await Doc.createdBy(req.body.name).first();
  await Doc.destroy({ where: { id: d.id } });
});
app.post('/b', async (req, res) => {
  const d = await db.createSession().findOne({ name: req.body.name });
  await Doc.destroy({ where: { id: d.id } });
});
app.post('/c', async (req, res) => {
  const d = await db.insertedDocs.findOne({ name: req.body.name });
  await Doc.destroy({ where: { id: d.id } });
});
"#;
        let lines = ownership_lines("javascript", src);
        for l in [3, 7, 11] {
            assert!(lines.contains(&l), "line {l} missing in {lines:?}");
        }
    }

    #[test]
    fn js_row_id_mixed_with_a_request_id_in_a_ternary_still_fires() {
        let src = r#"router.post("/docs", async (req, res) => {
  const row = await Document.findByPk(req.body.docId);
  const id = req.body.flag ? row.id : req.body.otherId;
  await Document.destroy({ where: { id } });
});
"#;
        assert!(ownership_lines("javascript", src).contains(&4));
    }
}
