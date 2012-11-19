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

class Users::OmniauthCallbacksControllerTest < ActionController::TestCase
  fixtures :users, :roles

  include OpenIdAuthentication

  def setup
    Setting.openid = 1
    OmniAuth.config.test_mode = true
    sign_out(:user)
    request.env["devise.mapping"] = Devise.mappings[:user]
  end

  def test_login_with_openid_for_existing_user
    with_settings :self_registration => 3 do
      mock_new_user_openid_authentication
      post :open_id
      assert_redirected_to '/my/page'
    end
  end

  def test_login_with_openid_for_existing_non_active_user
    with_settings :self_registration => 2 do
      mock_existen_user_openid_authentication
      @user.lock
      @user.save!
      post :open_id
      assert_redirected_to '/users/sign_in'
    end
  end

  def test_login_with_openid_with_new_user_created
    with_settings :self_registration => 3 do
      mock_new_user_openid_authentication
      post :open_id
      assert_redirected_to '/my/page'
    end
    user = User.find_by_login('newuser')
    assert user
    assert_equal 'New', user.firstname
    assert_equal 'User', user.lastname
  end

  def test_login_with_openid_with_new_user_and_self_registration_off
    with_settings :self_registration => 0 do
      mock_new_user_openid_authentication
      post :open_id
      assert_redirected_to '/users/sign_in'
    end
    user = User.find_by_login('newuser')
    assert_nil user
  end

  def test_login_with_openid_with_new_user_created_with_email_activation_should_have_a_confirmation_token
    with_settings :self_registration => 1 do
      mock_new_user_openid_authentication
      assert_difference 'ActionMailer::Base.deliveries.count', 1 do
        post :open_id
        assert_redirected_to '/users/sign_in'
      end
    end
    user = User.find_by_login('newuser')
    assert user
    assert user.confirmation_token.present?
    assert user.registered?
  end

  def test_login_with_openid_with_new_user_created_with_manual_activation
    with_settings :self_registration => 2 do
      mock_new_user_openid_authentication
      assert_difference 'ActionMailer::Base.deliveries.count', 1 do
        post :open_id
        assert_redirected_to '/users/sign_in'
      end
    end
    user = User.find_by_login('newuser')
    assert user
    assert_equal User::STATUS_REGISTERED, user.status
  end

  def test_login_with_openid_with_new_user_with_conflict_should_register
    user = users(:users_002)
    with_settings :self_registration => 3 do
      request.env["omniauth.auth"] = OmniAuth.config.mock_auth[:open_id] = OmniAuth::AuthHash.new({
        :provider => 'open_id',
        :uid => 'http://uid.another.net', # new identity_url
        :info => {
          :email => user.email, # same as existent
          :nickname => 'newuser',
          :name => 'New User'
        }
      })
      post :open_id
      assert_redirected_to '/users/register/sign_up'
      assert assigns(:user)
      assert_equal 'http://uid.another.net', assigns(:user)[:identity_url]
    end
  end

  def test_login_with_openid_with_new_user_with_missing_information_should_register
    with_settings :self_registration => 3 do
      mock_new_user_openid_authentication_with_invalid_data
      post :open_id
      assert_redirected_to '/users/register/sign_up'
      assert assigns(:user)
      assert_equal 'http://uid.unexistent.net', assigns(:user)[:identity_url]
    end
  end

  def test_setting_openid_should_return_true_when_set_to_true
    assert_equal true, Setting.openid?
  end

end
