# Redmine - project management software
# Copyright (C) 2006-2012  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require File.expand_path('../../../test_helper', __FILE__)

class Users::PasswordsControllerTest < ActionController::TestCase
  fixtures :users, :roles

  def setup
    @request.env["devise.mapping"] = Devise.mappings[:user]
    User.current = nil
  end

  def test_get_lost_password_should_display_lost_password_form
    get :new
    assert_response :success
    assert_select "input[name='user[login]']"
  end

  def test_lost_password_for_active_user_should_create_a_token
    ActionMailer::Base.deliveries.clear
    assert_difference 'ActionMailer::Base.deliveries.size' do
      post :create, :user => { :login => 'JSmith@somenet.foo' }
      assert_redirected_to new_user_session_path
    end

    token = User.find(2).reset_password_token
    assert token.present?

    assert_select_email do
      assert_select "a[href=?]", "http://example.com/users/password/edit?reset_password_token=#{token}"
    end
  end

  def test_lost_password_for_unknown_user_should_fail
    post :create, :user => { :login => 'invalid@somenet.foo' }
    assert_response :success
    assert_template :new
  end

  def test_lost_password_for_non_active_user_should_fail
    assert User.find(2).lock!

    post :create, :user => { :login => 'JSmith@somenet.foo' }
    assert_response :success
    assert_template :new
  end

  def test_get_lost_password_with_token_should_display_the_password_recovery_form
    user = User.find(2)
    user.send_reset_password_instructions

    get :edit, :reset_password_token => user.reset_password_token
    assert_response :success
    assert_template :edit

    assert_select "input[type=hidden][name='user[reset_password_token]'][value=?]", user.reset_password_token
  end

  def test_get_lost_password_with_invalid_token_should_render_edit_password_form
    get :edit, :reset_password_token => 'abcdef'
    assert_response :success
    assert_template :edit
  end

  def test_post_lost_password_with_token_should_change_the_user_password
    user = User.find(2)
    user.send_reset_password_instructions

    put :update, :user => {
      :reset_password_token => user.reset_password_token,
      :password => 'newpass123',
      :password_confirmation => 'newpass123'
    }
    assert_redirected_to user_root_path
    user.reload
    assert user.valid_password?('newpass123')
    assert_nil user.reset_password_token
  end

  def test_post_lost_password_with_token_for_non_active_user_should_fail
    user = User.find(2)
    user.lock!
    user.send_reset_password_instructions

    put :update, :user => {
      :reset_password_token => user.reset_password_token,
      :password => 'newpass123',
      :password_confirmation => 'newpass123'
    }

    assert_response :success
    assert_template :edit
    assert !user.valid_password?('newpass123')
  end

  def test_post_lost_password_with_token_and_password_confirmation_failure_should_redisplay_the_form
    user = User.find(2)
    user.send_reset_password_instructions

    put :update, :user => {
      :reset_password_token => user.reset_password_token,
      :password => 'newpass',
      :password_confirmation => 'wrongpass'
    }

    assert_response :success
    assert_template :edit
    assert_not_nil user.reset_password_token, "The reset_password_token was reset"

    assert_select "input[type=hidden][name='user[reset_password_token]'][value=?]", user.reset_password_token
  end

  def test_post_lost_password_with_invalid_token_should_render
    put :update, :user => {
      :reset_password_token => 'abcdef',
      :password => 'newpass123',
      :password_confirmation => 'newpass123'
    }
    assert_response :success
    assert_template :edit
  end
end
