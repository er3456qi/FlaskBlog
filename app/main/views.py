from flask import render_template, abort, flash, redirect, url_for, request
from flask_login import login_required, current_user, current_app

from . import main
from ..models import User, Role, Post, Permission, Comment
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, CommentForm
from app import db

from ..decorators import admin_required, permission_required


@main.route('/')
def index():
    query = current_user.followed_posts
    if query is None:
        query = Post.query
    page = request.args.get('page', 1, type=int)
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['BLOG_POSTS_PER_PAGE'])
    posts = pagination.items
    return render_template('index.html', posts=posts, pagination=pagination)


@main.route('/all')
@login_required
def show_all():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['BLOG_POSTS_PER_PAGE'])
    posts = pagination.items
    return render_template('index.html', posts=posts, pagination=pagination)


@main.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    return render_template('user.html', user=user, posts=posts)


@main.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated')
        return redirect(url_for('.user', username=current_user.username))
    form.username.data = current_user.username
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('settings.html', form=form)


@main.route('/settings/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('Your profile has been updated')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('settings.html', form=form, user=user)


@main.route('/newpost', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if current_user.can(Permission.WRITE_ARTICLES) and form.validate_on_submit():
        post = Post(title=form.title.data, body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        print('hello')
        return redirect(url_for('.index'))
    else:
        print('permission', current_user.can(Permission.WRITE_ARTICLES))
    return render_template('new_post.html', form=form)


@main.route('/post/<int:id>', methods=['GET', 'POST'])
def post(id):
    post = Post.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published')
        return redirect(url_for('.post', id=post.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (post.comments.count()-1) / current_app.config['BLOG_COMMENTS_PER_PAGE'] + 1
    pagination = post.comments.order_by(Comment.timestamp.asc()).\
            paginate(page, per_page=current_app.config['BLOG_COMMENTS_PER_PAGE'])
    comments = pagination.items
    return render_template('post.html', post=post, form=form, comments=comments, pagination=pagination)


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    if current_user != post.author and not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.body = form.body.data
        db.session.add(post)
        flash('The post has been updated')
        return redirect(url_for('post', id=post.id))
    form.title.data = post.title
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You have following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following {}'.format(username))
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You have not followed this user')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are now unfollowed {}'.format(username))
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User')
        return redirect(url_for('.index'))
    page=request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['BLOG_FOLLOWERS_PER_PAGE']
    )
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
                 for item in pagination.items]
    return render_template('followers.html',
                           user=user,
                           title='Followers of',
                           endpoint='.followers',
                           pagination=pagination,
                           follows=follows)


@main.route('/following/<username>')
def following(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid User')
        return redirect(url_for('.index'))
    page=request.args.get('page', 1, type=int)
    pagination = user.following.paginate(
        page, per_page=current_app.config['BLOG_FOLLOWERS_PER_PAGE']
    )
    follows = [{'user': item.following, 'timestamp': item.timestamp}
                 for item in pagination.items]
    return render_template('followers.html',
                           user=user,
                           title='Followed by',
                           endpoint='.following',
                           pagination=pagination,
                           follows=follows)


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc())\
                .paginate(page, per_page=current_app.config['BLOG_FOLLOWERS_PER_PAGE'])
    comments = pagination.items
    return render_template('moderate.html', comments=comments, pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    return redirect(url_for('.moderate', page=request.args.get('page', 1, type=int)))


@main.route('/delete_comment/<id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def delete_comment(id):
    comment = Comment.query.get_or_404(id)
    db.session.remove(comment)
    redirect(url_for('.index'))