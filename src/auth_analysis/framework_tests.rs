//! End-to-end tests for token lookups, actor identity and the Python, Ruby,
//! Rust and Java framework extractors.  Each case runs the whole auth pass over
//! an inline snippet.  A case that pins a suppression sits next to one that
//! keeps the finding for the shape beside it.

use super::test_support::findings_at;

fn rules(slug: &str, path: &str, src: &str) -> Vec<(String, usize)> {
    findings_at(slug, path, src)
}

/// Lines of `rule` findings, sorted and without repeats (one statement can
/// report both its read and its write).
fn lines(found: &[(String, usize)], rule: &str) -> Vec<usize> {
    let mut out: Vec<usize> = found
        .iter()
        .filter(|(id, _)| id == rule)
        .map(|(_, line)| *line)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn has(found: &[(String, usize)], rule: &str) -> bool {
    found.iter().any(|(id, _)| id == rule)
}

mod token_lookup {
    use super::*;

    #[test]
    fn orm_get_is_an_ownership_read_not_a_token_lookup() {
        let src = "\
from django.http import JsonResponse
from .models import Document


def update_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    doc.title = request.POST[\"title\"]
    doc.save()
    return JsonResponse({\"ok\": True})
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![6],
            "{found:?}"
        );
        assert!(
            !has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }

    #[test]
    fn dict_style_get_on_a_request_is_not_a_token_lookup() {
        let src = "\
from flask import Flask, request
from .db import Post, db

app = Flask(__name__)


@app.route(\"/posts\", methods=[\"POST\"])
def create_post():
    title = request.json.get(\"title\")
    post = Post(title=title)
    db.session.add(post)
    db.session.commit()
    return {\"ok\": True}
";
        let found = rules("python", "app.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn session_get_with_a_route_id_is_flagged() {
        let src = "\
from flask import Flask
from .db import User, db

app = Flask(__name__)


@app.route(\"/users/<user_id>/delete\", methods=[\"POST\"])
def delete_user(user_id):
    user = db.session.get(User, user_id)
    db.session.delete(user)
    db.session.commit()
    return {\"ok\": True}
";
        let found = rules("python", "app.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![9],
            "{found:?}"
        );
        assert!(
            !has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }

    #[test]
    fn get_on_a_queryset_chain_or_a_query_property_is_an_ownership_read() {
        let src = "\
from django.http import JsonResponse
from .models import Document, Note


def read_document(request, doc_id):
    doc = Document.objects.select_related(\"owner\").get(id=doc_id)
    return JsonResponse({\"t\": doc.title})


def read_note(request, note_id):
    note = Note.query.get(note_id)
    return JsonResponse({\"t\": note.title})
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![6, 11],
            "{found:?}"
        );
        assert!(
            !has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }

    #[test]
    fn dictionary_get_with_an_id_is_not_a_read_of_rows() {
        // `.get()` on a mapping, a cache or the request is a lookup in memory.
        let src = "\
from django.core.cache import cache
from django.http import JsonResponse


def lookup(request, doc_id, options, titles_by_id):
    title = titles_by_id.get(doc_id)
    cached = cache.get(doc_id)
    value = options.get(doc_id, None)
    other = request.GET.get(doc_id)
    return JsonResponse({\"t\": [title, cached, value, other]})
";
        let found = rules("python", "views.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn ruby_find_by_is_an_ownership_read_not_a_token_lookup() {
        let src = "\
class DocsController < ApplicationController
  def destroy
    doc = Document.find_by(id: params[:id])
    doc.destroy
  end

  def show
    @doc = Document.find_by!(id: params[:id])
  end
end
";
        let found = rules("ruby", "docs_controller.rb", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![3, 8],
            "{found:?}"
        );
        assert!(
            !has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }

    #[test]
    fn qualified_invitation_lookups_are_still_token_lookups() {
        let python = "\
class InvitationManager:
    def get(self, **kwargs):
        return kwargs


class Invitation:
    objects = InvitationManager()


def accept_invitation(request, token, role_override):
    invitation = Invitation.objects.get(token=token)
    return Membership.objects.create(
        workspace_id=invitation.workspace_id,
        role=role_override or invitation.requested_role,
    )
";
        let found = rules("python", "views.py", python);
        assert!(
            has(&found, "token_override_without_validation"),
            "{found:?}"
        );

        let ruby = "\
class InvitationsController < ApplicationController
  def accept
    invitation = Invitation.find_by(token: params[:token])
    if invitation.recipient_email == current_user.email
      Membership.create!(
        workspace_id: invitation.workspace_id,
        role: params[:role] || invitation.role
      )
    end
  end
end
";
        let found = rules("ruby", "invitations_controller.rb", ruby);
        assert!(
            has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }

    #[test]
    fn namespaced_invitation_lookup_matches_the_qualified_pattern() {
        let ruby = "\
class InvitationsController < ApplicationController
  def accept
    invitation = Accounts::Invitation.find_by(token: params[:token])
    Membership.create!(workspace_id: invitation.workspace_id, role: params[:role])
  end
end
";
        let found = rules("ruby", "invitations_controller.rb", ruby);
        assert!(
            has(&found, "token_override_without_validation"),
            "{found:?}"
        );
    }
}

mod actor {
    use super::*;

    #[test]
    fn rails_current_user_scoping_is_clean() {
        let src = "\
class NotesController < ApplicationController
  before_action :authenticate_user!

  def create
    note = Note.create(user_id: current_user.id, body: params[:body])
    render json: note
  end

  def index
    render json: Note.where(user_id: current_user.id)
  end

  def show
    @note = current_user.notes.find(params[:id])
  end

  def destroy
    current_user.notes.find(params[:id]).destroy
  end
end
";
        let found = rules("ruby", "notes_controller.rb", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rails_foreign_user_id_is_still_flagged() {
        let src = "\
class NotesController < ApplicationController
  before_action :authenticate_user!

  def index
    render json: Note.where(user_id: params[:user_id])
  end

  def destroy
    Note.find(params[:id]).destroy
  end
end
";
        let found = rules("ruby", "notes_controller.rb", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5, 9],
            "{found:?}"
        );
    }

    #[test]
    fn flask_login_current_user_forms_are_clean() {
        let src = "\
from flask import Flask
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route(\"/docs/<doc_id>\")
@login_required
def show_by_object(doc_id):
    doc = Doc.query.filter_by(id=doc_id, owner=current_user).first()
    return {\"t\": doc.title}


@app.route(\"/docs2/<doc_id>\")
@login_required
def show_by_id(doc_id):
    doc = Doc.query.filter_by(id=doc_id, owner_id=current_user.id).first()
    return {\"t\": doc.title}


@app.route(\"/docs3/<doc_id>\")
@login_required
def show_by_association(doc_id):
    doc = current_user.docs.filter_by(id=doc_id).first()
    return {\"t\": doc.title}
";
        let found = rules("python", "app.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn flask_query_without_the_caller_is_flagged() {
        let src = "\
from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route(\"/docs/<doc_id>\")
@login_required
def show_any(doc_id):
    doc = Doc.query.filter_by(id=doc_id).first()
    return {\"t\": doc.title}
";
        let found = rules("python", "app.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![10],
            "{found:?}"
        );
    }

    #[test]
    fn flask_g_user_is_the_caller() {
        let src = "\
from flask import Flask, g

app = Flask(__name__)


@app.route(\"/docs/<doc_id>\")
def show(doc_id):
    doc = Doc.query.filter_by(id=doc_id, owner_id=g.user.id).first()
    return {\"t\": doc.title}
";
        let found = rules("python", "app.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn django_request_user_object_and_association_are_clean() {
        let src = "\
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Document


@login_required
def show_by_object(request, doc_id):
    doc = Document.objects.filter(owner=request.user, id=doc_id).first()
    return JsonResponse({\"t\": doc.title})


@login_required
def show_by_association(request, doc_id):
    doc = request.user.documents.filter(id=doc_id).first()
    return JsonResponse({\"t\": doc.title})


@login_required
def show_by_pk(request, doc_id):
    doc = Document.objects.filter(owner_id=request.user.pk, id=doc_id).first()
    return JsonResponse({\"t\": doc.title})


@login_required
def show_any(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({\"t\": doc.title})
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![26],
            "{found:?}"
        );
    }

    #[test]
    fn express_req_user_object_is_the_caller() {
        let src = "\
const express = require('express');
const router = express.Router();
router.get('/docs/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, owner: req.user });
  res.json(doc);
});
router.get('/docs3/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.user._id });
  res.json(doc);
});
router.get('/docs4/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId });
  res.json(doc);
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![12],
            "{found:?}"
        );
    }

    #[test]
    fn request_supplied_owner_pins_are_not_the_caller() {
        let src = "\
const express = require('express');
const router = express.Router();
router.get('/read', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.query.ownerId });
  res.json(doc);
});
router.post('/reassign', async (req, res) => {
  await Doc.updateOne({ _id: req.params.docId }, { ownerId: req.body.ownerId });
  res.json({ ok: true });
});
router.get('/mine/:docId', async (req, res) => {
  const doc = await Doc.findOne({ _id: req.params.docId, ownerId: req.user.id });
  res.json(doc);
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![4, 8],
            "{found:?}"
        );
    }

    #[test]
    fn mongoose_update_document_owner_is_a_write_not_a_scope() {
        let src = "\
const express = require('express');
const router = express.Router();
router.post('/a/:id', requireLogin, async (req, res) => {
  await Note.findOneAndUpdate({ _id: req.params.id }, { owner: req.user.id });
  await Note.findByIdAndUpdate(req.params.id, { owner: req.user.id });
  await Note.updateOne({ _id: req.params.id }, { $set: { owner: req.user.id } });
  await Note.updateMany({ _id: req.params.id }, { $set: { owner: req.user.id } });
  res.json({ ok: true });
});
router.post('/b/:id', requireLogin, async (req, res) => {
  await Note.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, { title: req.body.title });
  await Note.updateOne({ _id: req.params.id, owner: req.user.id }, { $set: { title: req.body.title } });
  res.json({ ok: true });
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![4, 5, 6, 7],
            "{found:?}"
        );
    }

    #[test]
    fn rust_owner_compare_guard_and_derived_row_check_cover_the_request_id() {
        let src = "\
pub async fn edit(Json(data): Json<Edit>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  let orig = Message::read(&mut context.pool(), data.message_id).await?;
  if local_user_view.person.id != orig.creator_id {
    return Err(Denied.into());
  }
  Message::update(&mut context.pool(), data.message_id, &data.content).await?;
  Ok(Json(()))
}
pub async fn edit_bad(Json(data): Json<Edit>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  let orig = Message::read(&mut context.pool(), data.message_id).await?;
  Message::update(&mut context.pool(), data.message_id, &data.content).await?;
  Ok(Json(()))
}
pub async fn tag(Json(data): Json<Del>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  let tag = Tag::read(&mut context.pool(), data.tag_id).await?;
  let community = Community::read(&mut context.pool(), tag.community_id).await?;
  check_community_mod_action(&local_user_view, &community, false, &mut context.pool()).await?;
  Tag::update(&mut context.pool(), data.tag_id, &data.form).await?;
  Ok(Json(()))
}
pub async fn tag_bad(Json(data): Json<Del>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  let tag = Tag::read(&mut context.pool(), data.tag_id).await?;
  let community = Community::read(&mut context.pool(), data.other_id).await?;
  check_community_mod_action(&local_user_view, &community, false, &mut context.pool()).await?;
  Tag::update(&mut context.pool(), data.tag_id, &data.form).await?;
  Ok(Json(()))
}
";
        let found = rules("rust", "api.rs", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![10, 11, 22, 25],
            "{found:?}"
        );
    }

    #[test]
    fn route_parameter_named_owner_id_is_not_the_caller() {
        let src = "\
from fastapi import FastAPI

app = FastAPI()


@app.get(\"/docs/{doc_id}\")
def read_doc(doc_id: str, owner_id: str):
    return Doc.objects.filter(id=doc_id, owner_id=owner_id).first()
";
        let found = rules("python", "main.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![8],
            "{found:?}"
        );
    }
}

mod rails_filters {
    use super::*;

    fn ownership(src: &str) -> Vec<usize> {
        let found = rules("ruby", "notes_controller.rb", src);
        lines(&found, "missing_ownership_check")
    }

    #[test]
    fn only_with_percent_i_leaves_other_actions_unguarded() {
        let src = "\
class NotesController < ApplicationController
  before_action :authorize_owner!, only: %i[update destroy]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def archive
    note = Note.find(params[:id])
    note.update(archived: true)
  end
end
";
        assert_eq!(ownership(src), vec![10]);
    }

    #[test]
    fn only_with_symbols_and_percent_w_read_the_same_way() {
        let symbols = "\
class NotesController < ApplicationController
  before_action :authorize_owner!, only: [:update]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def archive
    note = Note.find(params[:id])
    note.update(archived: true)
  end
end
";
        assert_eq!(ownership(symbols), vec![10]);
        let words = symbols.replace("[:update]", "%w[update]");
        assert_eq!(ownership(&words), vec![10]);
    }

    #[test]
    fn except_excludes_the_listed_actions() {
        let src = "\
class NotesController < ApplicationController
  before_action :authorize_owner!, except: %i[index]

  def index
    @notes = Note.find(params[:id])
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        assert_eq!(ownership(src), vec![5]);
    }

    #[test]
    fn skip_before_action_only_removes_the_guard_from_the_listed_actions() {
        let src = "\
class NotesController < ApplicationController
  before_action :authorize_owner!
  skip_before_action :authorize_owner!, only: %i[preview]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def preview
    @note = Note.find(params[:id])
  end
end
";
        assert_eq!(ownership(src), vec![11]);
    }

    #[test]
    fn option_that_is_not_a_literal_list_proves_no_coverage() {
        // `only: ACTIONS` cannot be read, so the guard is not credited to
        // `update`, and the skip may have removed it from `update`.
        let guard = "\
class NotesController < ApplicationController
  before_action :authorize_owner!, only: GUARDED_ACTIONS

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        assert_eq!(ownership(guard), vec![5]);
        let skip = "\
class NotesController < ApplicationController
  before_action :authorize_owner!
  skip_before_action :authorize_owner!, only: OPEN_ACTIONS

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        assert_eq!(ownership(skip), vec![6]);
        // A literal list next to it is still read exactly.
        let literal_skip = skip.replace("OPEN_ACTIONS", "%i[preview]");
        assert!(ownership(&literal_skip).is_empty());
    }

    #[test]
    fn cancancan_macros_authorize_the_actions_they_cover() {
        let all = "\
class NotesController < ApplicationController
  load_and_authorize_resource

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        assert!(ownership(all).is_empty());

        let scoped = "\
class NotesController < ApplicationController
  load_and_authorize_resource only: %i[destroy]

  def destroy
    note = Note.find(params[:id])
    note.destroy
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        assert_eq!(ownership(scoped), vec![10]);
    }

    #[test]
    fn skip_authorize_resource_removes_the_macro() {
        let src = "\
class NotesController < ApplicationController
  load_and_authorize_resource
  skip_authorize_resource only: %i[preview]

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def preview
    @note = Note.find(params[:id])
  end
end
";
        assert_eq!(ownership(src), vec![11]);
    }

    #[test]
    fn policy_scope_and_accessible_by_confine_the_read() {
        let src = "\
class NotesController < ApplicationController
  def show
    @note = policy_scope(Note).find(params[:id])
  end

  def edit
    @note = Note.accessible_by(current_ability).find(params[:id])
  end

  def destroy
    @note = Note.find(params[:id])
  end
end
";
        assert_eq!(ownership(src), vec![11]);
    }
}

mod django {
    use super::*;

    #[test]
    fn view_decorators_apply_without_a_path_in_the_file() {
        let src = "\
from django.http import JsonResponse
from django.contrib.auth.decorators import permission_required, user_passes_test
from .models import Document


@permission_required(\"docs.delete_document\")
def delete_doc(request, doc_id):
    Document.objects.filter(id=doc_id).delete()
    return JsonResponse({\"ok\": True})


@user_passes_test(lambda u: u.is_staff)
def show_doc(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({\"t\": doc.title})
";
        let found = rules("python", "views.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn decorators_apply_to_flask_views_registered_with_add_url_rule() {
        let src = "\
from flask import Flask
from .auth import admin_required
from .models import Document

app = Flask(__name__)


@admin_required
def delete_doc(doc_id):
    Document.objects.filter(id=doc_id).delete()
    return {\"ok\": True}


app.add_url_rule(\"/docs/<doc_id>\", view_func=delete_doc, methods=[\"DELETE\"])
";
        let found = rules("python", "app.py", src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn login_only_decorator_does_not_authorize_a_foreign_id() {
        let src = "\
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Document


@login_required
def show_doc(request, doc_id):
    doc = Document.objects.filter(id=doc_id).first()
    return JsonResponse({\"t\": doc.title})
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![8],
            "{found:?}"
        );
    }

    #[test]
    fn drf_views_are_analysed() {
        let src = "\
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Document


class DocumentDetail(APIView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return Response(status=204)


class DocumentViewSet(viewsets.ViewSet):
    def destroy(self, request, pk=None):
        Document.objects.filter(pk=pk).delete()
        return Response(status=204)
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![9, 15],
            "{found:?}"
        );
    }

    #[test]
    fn drf_permission_classes_authorize_the_view() {
        let object_level = "\
from rest_framework.permissions import DjangoObjectPermissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Document


class DocumentDetail(APIView):
    permission_classes = [DjangoObjectPermissions]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return Response(status=204)
";
        let found = rules("python", "views.py", object_level);
        assert!(found.is_empty(), "{found:?}");

        // Login alone proves who is calling, not that the row is theirs.
        let login_only = object_level.replace("DjangoObjectPermissions", "IsAuthenticated");
        let found = rules("python", "views.py", &login_only);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![11],
            "{found:?}"
        );
    }

    #[test]
    fn drf_permission_class_or_is_as_weak_as_its_weaker_side() {
        let src = "\
from rest_framework.permissions import DjangoObjectPermissions, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Document


class AnyUser(APIView):
    permission_classes = [IsAuthenticated | IsAdminUser]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()


class AdminOrObject(APIView):
    permission_classes = [IsAdminUser | DjangoObjectPermissions]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()


class Both(APIView):
    permission_classes = [IsAuthenticated & DjangoObjectPermissions]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()


class NotAdmin(APIView):
    permission_classes = [~IsAdminUser]

    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
";
        let found = rules("python", "views.py", src);
        // `IsAuthenticated | IsAdminUser` admits any signed-in user, and
        // `~IsAdminUser` grants nothing; the other two authorize the row.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![11, 32],
            "{found:?}"
        );
    }

    #[test]
    fn view_classes_with_a_project_base_are_left_alone() {
        // `ObjectView` may carry permission classes or a restricted queryset
        // that this file does not show.
        let src = "\
from rest_framework.views import APIView
from .base import ObjectView
from .models import Document


class ProjectBase(ObjectView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()


class MixedBases(ObjectView, APIView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()


class FrameworkOnly(APIView):
    def delete(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![18],
            "{found:?}"
        );
    }

    #[test]
    fn flask_method_view_decorators_guard_the_class() {
        let src = "\
from flask.views import MethodView
from flask_login import login_required
from .models import Document


class DocumentAPI(MethodView):
    decorators = [login_required]

    def delete(self, doc_id):
        Document.objects.filter(id=doc_id).delete()
";
        let found = rules("python", "views.py", src);
        // `login_required` is authentication only, so the foreign id stays flagged.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![10],
            "{found:?}"
        );
    }

    #[test]
    fn mixin_and_method_decorator_guards_apply_to_class_views() {
        let src = "\
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import JsonResponse
from django.views import View
from .models import Document


class DeleteDocument(PermissionRequiredMixin, View):
    permission_required = 'docs.delete_document'

    def post(self, request, doc_id):
        Document.objects.filter(id=doc_id).delete()
        return JsonResponse({})
";
        let found = rules("python", "views.py", src);
        assert!(found.is_empty(), "{found:?}");
    }
}

mod rust_routes {
    use super::*;

    fn found(src: &str) -> Vec<(String, usize)> {
        rules("rust", "main.rs", src)
    }

    #[test]
    fn axum_route_layer_covers_the_routes_added_before_it() {
        let src = "\
use axum::{Router, extract::{Path, State}, middleware, routing::delete};

async fn delete_user(Path(user_id): Path<String>, State(db): State<Db>) {
    db.delete_user(&user_id).await;
}

async fn delete_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn router() -> Router {
    Router::new()
        .route(\"/admin/users/:user_id\", delete(delete_user))
        .route_layer(middleware::from_fn(require_admin))
        .route(\"/docs/:doc_id\", delete(delete_doc))
        .route_layer(middleware::from_fn(require_doc_owner))
}
";
        let found = found(src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn axum_route_added_after_a_layer_is_not_covered_by_it() {
        let src = "\
use axum::{Router, extract::{Path, State}, middleware, routing::delete};

async fn delete_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

async fn delete_note(Path(note_id): Path<String>, State(db): State<Db>) {
    db.delete_note(&note_id).await;
}

fn router() -> Router {
    Router::new()
        .route(\"/docs/:doc_id\", delete(delete_doc))
        .route_layer(middleware::from_fn(require_doc_owner))
        .route(\"/notes/:note_id\", delete(delete_note))
}
";
        let found = found(src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![8],
            "{found:?}"
        );
    }

    #[test]
    fn axum_layer_written_before_the_route_covers_nothing() {
        let src = "\
use axum::{Router, extract::{Path, State}, middleware, routing::delete};

async fn delete_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn router() -> Router {
    Router::new()
        .layer(middleware::from_fn(require_doc_owner))
        .route(\"/docs/:doc_id\", delete(delete_doc))
}
";
        let found = found(src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![4],
            "{found:?}"
        );
    }

    #[test]
    fn axum_method_router_layer_covers_its_handler() {
        let src = "\
use axum::{Router, extract::{Path, State}, middleware, routing::delete};

async fn delete_doc(Path(doc_id): Path<String>, State(db): State<Db>) {
    db.delete_doc(&doc_id).await;
}

fn router() -> Router {
    Router::new().route(
        \"/docs/:doc_id\",
        delete(delete_doc).route_layer(middleware::from_fn(require_doc_owner)),
    )
}
";
        let found = found(src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn axum_admin_layer_satisfies_the_admin_route_rule() {
        let src = "\
use axum::{Router, middleware, routing::get};

async fn stats() {
    stats_service::dump();
}

async fn secrets() {
    stats_service::dump();
}

fn router() -> Router {
    Router::new()
        .route(\"/admin/stats\", get(stats))
        .route_layer(middleware::from_fn(require_admin))
        .route(\"/admin/secrets\", get(secrets))
        .route_layer(middleware::from_fn(require_login))
}
";
        let found = found(src);
        // `route_layer(require_login)` is the outer layer, so it covers both
        // routes; only `/admin/stats` also has the admin layer.
        assert_eq!(
            lines(&found, "admin_route_missing_admin_check").len(),
            1,
            "{found:?}"
        );
    }

    #[test]
    fn actix_to_route_registers_the_handler() {
        let src = "\
use actix_web::web;

async fn remove_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/docs/{doc_id}\", web::delete().to(remove_doc));
}
";
        let found = found(src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5],
            "{found:?}"
        );
    }

    #[test]
    fn actix_wrap_on_the_scope_covers_its_routes() {
        let src = "\
use actix_web::web;

async fn remove_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope(\"/docs\")
            .wrap(require_doc_owner)
            .route(\"/{doc_id}\", web::delete().to(remove_doc)),
    );
}
";
        let found = found(src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn actix_wrap_after_the_route_still_covers_it() {
        let src = "\
use actix_web::web;

async fn remove_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope(\"/docs\")
            .route(\"/{doc_id}\", web::delete().to(remove_doc))
            .wrap(require_doc_owner),
    );
}
";
        let found = found(src);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn actix_login_only_wrap_is_not_ownership() {
        let src = "\
use actix_web::web;

async fn remove_doc(p: web::Path<String>, db: web::Data<Db>) {
    let doc_id = p.into_inner();
    db.delete_doc(&doc_id).await;
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope(\"/docs\")
            .wrap(require_login)
            .route(\"/{doc_id}\", web::delete().to(remove_doc)),
    );
}
";
        let found = found(src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5],
            "{found:?}"
        );
    }

    #[test]
    fn actix_admin_scope_wrap_satisfies_the_admin_route_rule() {
        let src = "\
use actix_web::web;

async fn stats() {
    stats_service::dump();
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope(\"/admin\")
            .wrap(require_admin)
            .route(\"/stats\", web::get().to(stats)),
    );
}
";
        let found = found(src);
        assert!(!has(&found, "admin_route_missing_admin_check"), "{found:?}");
    }
}

mod spring {
    use super::*;

    fn ownership(src: &str) -> Vec<usize> {
        let found = rules("java", "DocController.java", src);
        lines(&found, "missing_ownership_check")
    }

    #[test]
    fn multi_line_pre_authorize_is_read() {
        let src = "\
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping(\"/api/docs\")
public class DocController {
    private final DocRepository docRepository;

    @GetMapping(\"/{docId}\")
    @PreAuthorize(\"@docSecurity.isOwner(#docId, authentication)\")
    public Doc single(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    @GetMapping(\"/b/{docId}\")
    @PreAuthorize(
        \"@docSecurity.isOwner(#docId, authentication)\"
    )
    public Doc wrapped(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    // a comment between annotations must not end the scan
    @GetMapping(\"/c/{docId}\")
    // second comment
    @PreAuthorize(\"@docSecurity.isOwner(#docId, authentication)\"
        + \" and hasRole('USER')\")
    public Doc concatenated(@PathVariable String docId) {
        return docRepository.findById(docId).orElseThrow();
    }

    @DeleteMapping(\"/d/{docId}\")
    public void unguarded(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }
}
";
        assert_eq!(ownership(src), vec![36]);
    }

    #[test]
    fn has_any_role_with_an_admin_role_authorizes() {
        let src = "\
package com.example;

@RestController
@RequestMapping(\"/api/docs\")
public class DocController {
    private final DocRepository docRepository;

    @DeleteMapping(\"/c/{docId}\")
    @PreAuthorize(\"hasAnyRole('ADMIN', 'MANAGER')\")
    public void admins(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping(\"/e/{docId}\")
    @PreAuthorize(\"hasAnyAuthority('ROLE_ADMIN')\")
    public void authorities(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping(\"/f/{docId}\")
    @PreAuthorize(\"hasAnyRole('USER', 'EDITOR')\")
    public void anyUserRole(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }

    @DeleteMapping(\"/g/{docId}\")
    @PreAuthorize(\"hasRole('ADMIN') or hasRole('USER')\")
    public void adminOrUser(@PathVariable String docId) {
        docRepository.deleteById(docId);
    }
}
";
        // A role list that names no admin or manager role proves login, not
        // ownership, and so does an `or` with a plain user role.
        assert_eq!(ownership(src), vec![23, 29]);
    }

    #[test]
    fn has_any_role_on_an_admin_path_is_an_admin_guard() {
        let src = "\
package com.example;

@RestController
@RequestMapping(\"/admin/reports\")
public class AdminReportController {
    private final ReportRepository reportRepository;

    @GetMapping(\"/export\")
    @PreAuthorize(\"hasAnyRole('USER', 'AUDITOR')\")
    public Object notAdmin() {
        return reportRepository.findAll();
    }

    @GetMapping(\"/purge\")
    @PreAuthorize(\"hasAnyRole('ADMIN', 'MANAGER')\")
    public Object admin() {
        return reportRepository.findAll();
    }

    @GetMapping(\"/archive\")
    @PreAuthorize(\"hasAnyRole('ADMIN', 'USER')\")
    public Object anyUser() {
        return reportRepository.findAll();
    }
}
";
        let found = rules("java", "AdminReportController.java", src);
        // Only the list made of admin roles keeps a plain user out.
        assert_eq!(
            lines(&found, "admin_route_missing_admin_check"),
            vec![8, 20],
            "{found:?}"
        );
    }
}

mod js_roles {
    use super::*;

    #[test]
    fn role_middleware_naming_an_admin_role_is_an_admin_guard() {
        let src = "\
const express = require('express');
const passport = require('passport');
const router = express.Router();

router.get('/admin/users', passport.authenticate('jwt'), authorize('admin'), async (req, res) => {
  res.json(await User.find());
});

router.get('/admin/stats', requireAuth, checkRole(['admin']), async (req, res) => {
  res.json(await Stats.find());
});

router.get('/admin/audit', requireAuth, restrictTo('admin'), async (req, res) => {
  res.json(await Audit.find());
});

router.get('/admin/logs', requireAuth, async (req, res) => {
  res.json(await Log.find());
});

router.get('/admin/reports', requireAuth, checkRole(['viewer']), async (req, res) => {
  res.json(await Report.find());
});

router.get('/admin/exports', requireAuth, checkRole(['admin', 'viewer']), async (req, res) => {
  res.json(await Export.find());
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", src);
        // A role list admits any role it names, so `viewer` beside `admin`
        // still lets a non-admin in.
        assert_eq!(
            lines(&found, "admin_route_missing_admin_check"),
            vec![17, 21, 25],
            "{found:?}"
        );
    }
}

mod caller_scope_limits {
    use super::*;

    #[test]
    fn rails_association_writes_and_model_lookups_are_not_scoped_by_the_caller() {
        let src = "\
class MembershipsController < ApplicationController
  before_action :authenticate_user!

  def create
    current_user.memberships.create(project_id: params[:project_id])
  end

  def show
    current_user.class.find(params[:id])
  end

  def mine
    current_user.memberships.find(params[:id])
  end

  def comment
    Comment.create(post_id: params[:post_id], author: current_user)
  end

  def rename
    Note.where(user: current_user, id: params[:id]).update_all(body: params[:body])
  end

  def claim
    Note.where(id: params[:id]).update_all(user_id: current_user)
  end
end
";
        let found = rules("ruby", "memberships_controller.rb", src);
        // The association lookup on line 12 and the write through a
        // caller-pinned `where` on line 21 stay clean. The caller stored as
        // the written value on line 25 pins nothing.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5, 9, 17, 25],
            "{found:?}"
        );
    }

    #[test]
    fn django_whole_user_kwarg_is_a_pin_for_a_lookup_not_for_a_write() {
        let src = "\
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Document, Share, Task


@login_required
def new_task(request, project_id):
    Task.objects.create(project_id=project_id, created_by=request.user)
    return JsonResponse({})


@login_required
def share(request, doc_id):
    Share.objects.create(document_id=doc_id, shared_by=request.user)
    return JsonResponse({})


@login_required
def favorite(request, doc_id):
    request.user.favorites.create(document_id=doc_id)
    return JsonResponse({})


@login_required
def mine(request, doc_id):
    doc = Document.objects.filter(owner=request.user, id=doc_id).first()
    return JsonResponse({\"t\": doc.title})


@login_required
def rename(request, doc_id):
    Document.objects.filter(owner=request.user, id=doc_id).update(title='x')
    return JsonResponse({})


@login_required
def claim(request, doc_id):
    Document.objects.filter(id=doc_id).update(owner=request.user)
    return JsonResponse({})
";
        let found = rules("python", "views.py", src);
        // A write through a caller-pinned filter (line 32) is scoped; the
        // caller stored as the written value (line 38) is not a pin.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![8, 14, 20, 38],
            "{found:?}"
        );
    }

    #[test]
    fn express_association_writes_and_model_lookups_are_not_scoped() {
        let src = "\
const express = require('express');
const router = express.Router();

router.post('/memberships', requireAuth, async (req, res) => {
  await req.user.createMembership({ projectId: req.body.projectId });
  res.json({});
});

router.get('/docs/:docId', requireAuth, async (req, res) => {
  res.json(await req.user.constructor.findById(req.params.docId));
});

router.get('/mine/:docId', requireAuth, async (req, res) => {
  res.json(await req.user.getDocuments({ where: { id: req.params.docId } }));
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5, 10],
            "{found:?}"
        );
    }

    #[test]
    fn python_gets_on_querysets_and_model_classes_are_ownership_reads() {
        let src = "\
from rest_framework import viewsets
from rest_framework.response import Response
from .models import Note


class NoteViewSet(viewsets.ViewSet):
    def retrieve(self, request, pk=None):
        obj = self.queryset.get(pk=pk)
        return Response(obj.title)

    def update(self, request, pk=None):
        qs = Note.objects.all()
        obj = qs.get(pk=pk)
        return Response(obj.title)

    def destroy(self, request, pk=None):
        note = Note.get_by_id(pk)
        note.delete_instance()
        return Response(status=204)

    def options(self, request, pk=None):
        settings = {}
        return Response(settings.get(pk))
";
        let found = rules("python", "views.py", src);
        // The three row lookups; the dictionary `get` stays out.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![8, 13, 17],
            "{found:?}"
        );
    }

    #[test]
    fn authorize_resource_authorizes_the_class_not_the_row() {
        let src = "\
class NotesController < ApplicationController
  authorize_resource only: %i[destroy]
  load_and_authorize_resource only: %i[update]

  def destroy
    note = Note.find(params[:id])
    note.destroy
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end
end
";
        let found = rules("ruby", "notes_controller.rb", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![6],
            "{found:?}"
        );
    }

    #[test]
    fn model_permissions_do_not_scope_rows_and_read_only_variants_do_not_guard_reads() {
        let model = "\
from rest_framework import viewsets
from rest_framework.permissions import DjangoModelPermissions
from .models import Note


class NoteViewSet(viewsets.ModelViewSet):
    permission_classes = [DjangoModelPermissions]

    def destroy(self, request, pk=None):
        Note.objects.filter(pk=pk).delete()
";
        let found = rules("python", "views.py", model);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![10],
            "{found:?}"
        );

        let read_only = "\
from rest_framework import viewsets
from rest_framework.permissions import DjangoObjectPermissions, IsAuthenticatedOrReadOnly
from .models import Note


class NoteViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def retrieve(self, request, pk=None):
        return Note.objects.get(pk=pk)

    def destroy(self, request, pk=None):
        Note.objects.filter(pk=pk).delete()
";
        let found = rules("python", "views.py", read_only);
        // Login is required for the delete only, and login is not ownership.
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![10, 13],
            "{found:?}"
        );
    }

    #[test]
    fn action_permission_override_and_get_permissions_replace_the_class_list() {
        let src = "\
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, DjangoObjectPermissions
from .models import Document


class DocViewSet(viewsets.ModelViewSet):
    permission_classes = [DjangoObjectPermissions]

    def destroy(self, request, pk=None):
        Document.objects.filter(pk=pk).delete()

    @action(detail=True, permission_classes=[AllowAny])
    def export(self, request, pk=None):
        return Document.objects.get(pk=pk)

    @action(detail=True, permission_classes=[DjangoObjectPermissions])
    def archive(self, request, pk=None):
        return Document.objects.get(pk=pk)


class DynamicViewSet(viewsets.ModelViewSet):
    permission_classes = [DjangoObjectPermissions]

    def get_permissions(self):
        return [AllowAny()]

    def destroy(self, request, pk=None):
        Document.objects.filter(pk=pk).delete()
";
        let found = rules("python", "views.py", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![15, 29],
            "{found:?}"
        );
    }

    #[test]
    fn injected_current_user_id_stays_the_caller() {
        let fastapi = "\
from fastapi import APIRouter, Depends

router = APIRouter()


@router.put(\"/items/{item_id}\")
def update(item_id: int, current_user_id: int = Depends(get_user_id)):
    return db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user_id).first()
";
        let found = rules("python", "app.py", fastapi);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
    }

    #[test]
    fn role_lists_and_substring_roles_are_not_admin_guards() {
        let java = "\
package com.example;

@RestController
@RequestMapping(\"/admin/reports\")
public class AdminReportController {
    private final ReportRepository reportRepository;

    @GetMapping(\"/a\")
    @Secured({\"ROLE_ADMIN\", \"ROLE_USER\"})
    public Object mixed() {
        return reportRepository.findAll();
    }

    @GetMapping(\"/b\")
    @RolesAllowed({\"ADMIN\", \"USER\"})
    public Object mixedJsr() {
        return reportRepository.findAll();
    }

    @GetMapping(\"/c\")
    @PreAuthorize(\"hasRole('MANAGE_OWN_NOTES')\")
    public Object narrow() {
        return reportRepository.findAll();
    }

    @GetMapping(\"/d\")
    @Secured({\"ROLE_ADMIN\", \"ROLE_SUPERUSER\"})
    public Object admins() {
        return reportRepository.findAll();
    }
}
";
        let found = rules("java", "AdminReportController.java", java);
        assert_eq!(
            lines(&found, "admin_route_missing_admin_check"),
            vec![8, 14, 20],
            "{found:?}"
        );

        let js = "\
const express = require('express');
const router = express.Router();

router.delete('/admin/users/:id', requireAuth, requireRoles('viewer'), async (req, res) => {
  res.json(await User.find());
});

router.delete('/admin/teams/:id', requireAuth, requireRoles('admin'), async (req, res) => {
  res.json(await Team.find());
});
module.exports = router;
";
        let found = rules("javascript", "routes.js", js);
        assert_eq!(
            lines(&found, "admin_route_missing_admin_check"),
            vec![4],
            "{found:?}"
        );
    }

    #[test]
    fn rust_body_admin_gate_with_try_dominates_later_operations() {
        let src = "\
pub async fn purge(Json(data): Json<Purge>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  is_admin(&local_user_view)?;
  Community::delete(&mut context.pool(), data.community_id).await?;
  Ok(())
}
";
        let found = rules("rust", "purge.rs", src);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
    }

    #[test]
    fn rust_admin_gate_that_does_not_dominate_keeps_the_finding() {
        let src = "\
pub async fn conditional(Json(data): Json<Purge>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  if data.reason.is_some() {
    is_admin(&local_user_view)?;
  }
  Community::delete(&mut context.pool(), data.community_id).await?;
  Ok(())
}

pub async fn ignored(Json(data): Json<Purge>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  let _ok = is_admin(&local_user_view).is_ok();
  Community::delete(&mut context.pool(), data.community_id).await?;
  Ok(())
}

pub async fn late(Json(data): Json<Purge>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  Community::delete(&mut context.pool(), data.community_id).await?;
  is_admin(&local_user_view)?;
  Ok(())
}
";
        let found = rules("rust", "purge.rs", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5, 11, 16],
            "{found:?}"
        );
    }

    #[test]
    fn rust_nested_self_actor_id_alias_and_viewer_read_are_scoped() {
        let src = "\
pub async fn ban(Json(data): Json<Ban>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  check_local_user_valid(&local_user_view)?;
  let my_person_id = local_user_view.person.id;
  let pv = PersonView::read(&mut context.pool(), data.person_id, Some(my_person_id), true).await?;
  let cv = CommentView::read(&mut context.pool(), data.comment_id, Some(&local_user_view.local_user), 1).await?;
  Ok(())
}

pub async fn del(Json(data): Json<Del>, context: Data<Ctx>, local_user_view: LocalUserView) -> R {
  check_local_user_valid(&local_user_view)?;
  Comment::delete(&mut context.pool(), data.comment_id, Some(&local_user_view.local_user)).await?;
  Ok(())
}
";
        let found = rules("rust", "ban.rs", src);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![11],
            "{found:?}"
        );
    }

    #[test]
    fn python_migrations_and_private_helpers_are_not_entry_points() {
        let migration = "\
def fix_statuses(Checkout, empty_ids):
    return Checkout.objects.filter(pk__in=empty_ids)
";
        let found = rules("python", "app/migrations/0060_fix.py", migration);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
        let found = rules("python", "app/helpers.py", migration);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![2],
            "{found:?}"
        );
        // A private helper that only a task calls is internal.
        let private = "\
def _raw_remove(deliveries_ids):
    return Delivery.objects.filter(id__in=deliveries_ids)

def cleanup_task(batch):
    return _raw_remove(batch)
";
        let found = rules("python", "app/tasks.py", private);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
        // The same helper reached from a route handler keeps its finding, as
        // does a private helper with no in-file caller (it may be imported).
        let routed = "\
from fastapi import APIRouter
router = APIRouter()

def _raw_remove(deliveries_ids):
    return Delivery.objects.filter(id__in=deliveries_ids)

def _orphan(deliveries_ids):
    return Delivery.objects.filter(id__in=deliveries_ids)

@router.delete('/deliveries')
def remove(ids: list):
    return _raw_remove(ids)
";
        let found = rules("python", "app/api.py", routed);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![5, 8],
            "{found:?}"
        );
    }

    #[test]
    fn peewee_and_tortoise_model_get_is_a_row_read() {
        let peewee = "\
from flask import Flask
from peewee import Model

app = Flask(__name__)


class Base(Model):
    pass


class Note(Base):
    pass


@app.route('/notes/<int:note_id>')
def show(note_id):
    return Note.get(Note.id == note_id).title
";
        let found = rules("python", "views.py", peewee);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![17],
            "{found:?}"
        );
        let tortoise = "\
from fastapi import FastAPI
from tortoise.models import Model

app = FastAPI()


class Note(Model):
    pass


@app.get('/notes/{note_id}')
async def show(note_id: str):
    return await Note.get(id=note_id)
";
        let found = rules("python", "views.py", tortoise);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![13],
            "{found:?}"
        );
        let other = "\
from flask import Flask
from pydantic import BaseModel

app = Flask(__name__)


class Cache(BaseModel):
    pass


@app.route('/c/<key>')
def show(key):
    return Cache.get(key)
";
        let found = rules("python", "views.py", other);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
    }

    #[test]
    fn fastify_shorthand_needs_provenance_for_generic_receivers() {
        let mirage = "\
export default function mockServer(server) {
  server.get('/posts/:id', function ({posts}, {params}) {
    return posts.find(params.id);
  });
}
";
        let found = rules("javascript", "mirage/config.js", mirage);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
        let real = "\
const fastify = require('fastify');
const server = fastify();
server.get('/posts/:id', async (request) => {
  return Post.findByPk(request.params.id);
});
";
        let found = rules("javascript", "app.js", real);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![4],
            "{found:?}"
        );
        let plugin = "\
module.exports = async function (server, opts) {
  server.get('/posts/:id', async (request) => {
    return Post.findByPk(request.params.id);
  });
};
";
        let found = rules("javascript", "plugin.js", plugin);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![3],
            "{found:?}"
        );
    }

    #[test]
    fn bare_react_import_with_a_hook_marks_a_file_as_browser_code() {
        let src = "\
import {useEffect} from 'react';
export const Page = ({postId}) => { useEffect(() => { send({postId}); }); return null; };
export async function send({postId}, api) {
  await api.feedback.add({postId});
}
";
        let found = rules("javascript", "page.js", src);
        assert!(
            lines(&found, "missing_ownership_check").is_empty(),
            "{found:?}"
        );
        // No hook call: could be a server component, so the call stays flagged.
        let server = "\
import {cache} from 'react';
export async function send({postId}, api) {
  await api.feedback.add({postId});
}
";
        let found = rules("javascript", "page.js", server);
        assert_eq!(
            lines(&found, "missing_ownership_check"),
            vec![3],
            "{found:?}"
        );
    }
}
