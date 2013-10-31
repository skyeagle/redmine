# Redmine - project management software
# Copyright (C) 2006-2013  Jean-Philippe Lang
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

require File.expand_path('../../test_helper', __FILE__)

begin
  require 'mocha/setup'
rescue
  # Won't run some tests
end

class AccountTest < ActionController::IntegrationTest
  fixtures :users, :roles

  include OpenIdAuthentication

  setup do
    OmniAuth.config.test_mode = true
  end

  # Replace this with your real tests.
  def test_login
    get "my/page"
    assert_redirected_to "/users/sign_in?back_url=http%3A%2F%2Fwww.example.com%2Fmy%2Fpage"
    user = User.find_first_by_auth_conditions(:login => 'jsmith')
    assert user.valid?
    log_user('jsmith', 'jsmith')

    get "my/account"
    assert_response :success
    assert_template "my/account"
  end

  def test_autologin
    user = User.find(1)
    Devise.remember_for = 7.days

    # User logs in with 'remember_me' checked
    post '/users/sign_in', :user => { :login => user.login, :password => 'admin', :remember_me => 1 }
    assert_redirected_to '/my/page'
    assert cookies["remember_user_token"]

    # Session is cleared
    reset!
    # Clears user's last login timestamp
    user.update_attribute :last_sign_in_at, nil
    assert_nil user.reload.last_sign_in_at
    assert_nil cookies["remember_user_token"]

    get "my/page"
    assert_redirected_to "/users/sign_in?back_url=http%3A%2F%2Fwww.example.com%2Fmy%2Fpage"

    # User comes back with his remember_me cookie
    raw_cookie = User.serialize_into_cookie(user)
    cookies['remember_user_token'] = generate_signed_cookie(raw_cookie)
    get '/my/page'
    assert_response :success
    assert_template 'my/page'
    assert @request.session['warden.user.user.key'].include?([user.id])
    assert_not_nil user.reload.last_sign_in_at
  end

  def test_lost_password
    get "/users/password/new"
    assert_response :success
    assert_template "users/passwords/new"
    assert_select "input[name='user[login]']"

    post "/users/password", :user => { :login => 'jSmith@somenet.foo' }
    assert_redirected_to "/users/sign_in"

    token = nil
    assert_select_email do
      token = assert_select('a').first['href'].match(/\=(.+)$/)[1]
    end

    get "/users/password/edit", :reset_password_token => token
    assert_response :success
    assert_template "users/passwords/edit"
    assert_select "input[type=hidden][name='user[reset_password_token]'][value=?]", token
    assert_select "input[name='user[password]']"
    assert_select "input[name='user[password_confirmation]']"

    put "users/password", :user => {
      :reset_password_token => token,
      :password => 'newpass123',
      :password_confirmation => 'newpass123'
    }
    assert_redirected_to "/my/page"
    assert_equal 'Your password was changed successfully. You are now signed in.', flash[:notice]

    user = User.find_first_by_auth_conditions(:login => 'jsmith@somenet.foo')
    assert_equal token, user.reset_password_token
  end

  def test_register_with_automatic_activation
    Setting.self_registration = '3'

    get 'users/register/sign_up'
    assert_response :success
    assert_template 'users/registrations/new'

    assert_no_difference 'ActionMailer::Base.deliveries.count' do
      post 'users/register', :user => {
        :login => "newuser",
        :language => "en",
        :firstname => "New",
        :lastname => "User",
        :email => "newuser@foo.bar",
        :password => "newpass123",
        :password_confirmation => "newpass123"
      }
    end
    assert_redirected_to '/my/account'
    follow_redirect!
    assert_response :success
    assert_template 'my/account'

    user = User.find_first_by_auth_conditions(:login => 'newuser')
    assert_not_nil user
    assert user.active?
    assert user.active_for_authentication?
    assert_not_nil user.last_sign_in_at
  end

  def test_register_with_manual_activation
    Setting.self_registration = '2'

    # account activation request for admin
    assert_difference 'ActionMailer::Base.deliveries.count', 1 do
      post 'users/register', :user => {
        :login => "newuser",
        :language => "en",
        :firstname => "New",
        :lastname => "User",
        :email => "newuser@foo.bar",
        :password => "newpass123",
        :password_confirmation => "newpass123"
      }
    end
    user = User.where(:login => 'newuser').first
    assert_redirected_to '/'
    assert !user.active?
    assert !user.active_for_authentication?
  end

  def test_register_with_email_activation
    Setting.self_registration = '1'

    assert_difference 'ActionMailer::Base.deliveries.count', 1 do
      post 'users/register', :user => {
        :login => "newuser",
        :language => "en",
        :firstname => "New",
        :lastname => "User",
        :email => "newuser@foo.bar",
        :password => "newpass123",
        :password_confirmation => "newpass123"
      }
    end
    user = User.where(:login => 'newuser').first
    assert_redirected_to '/'
    assert !user.active?

    assert_equal 'newuser@foo.bar', user.email
    assert !user.send(:confirmation_period_valid?)

    token = nil
    assert_select_email do
      token = assert_select('a').first['href'].match(/\=(.+)$/)[1]
    end

    get 'users/confirmation', :confirmation_token => token
    assert_redirected_to '/my/page'
    user.reload
    assert user.active?
    assert user.active_for_authentication?
  end

  def test_login_by_openid_when_it_disabled_for_existent_user
    with_settings :self_registration => 3, :openid => 0 do
      post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
      assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

      mock_existen_user_openid_authentication
      follow_redirect!
      assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
      follow_redirect!
      assert_redirected_to "/users/register/sign_up"
    end
  end

  def test_login_by_openid_when_it_enabled_for_existent_user
    with_settings :self_registration => 3, :openid => 1 do
      post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
      assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

      mock_existen_user_openid_authentication
      follow_redirect!
      assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
      follow_redirect!
      assert_redirected_to "/my/page"
    end
  end

  def test_login_by_openid_when_it_disabled_for_new_user
    with_settings :self_registration => 3, :openid => 0 do
      post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
      assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

      mock_new_user_openid_authentication
      follow_redirect!
      assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
      follow_redirect!
      assert_redirected_to "/users/register/sign_up"
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_and_auto_activation
    with_settings :self_registration => 3, :openid => 1 do
      assert_no_difference 'ActionMailer::Base.deliveries.count' do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/my/page"
        user = User.where(:email => 'abc@abc.com').first
        assert user.active?
      end
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_with_validation_failed_and_activation_by_email
    with_settings :self_registration => 1, :openid => 1 do
      assert_no_difference 'ActionMailer::Base.deliveries.count' do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication_with_invalid_data
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/users/register/sign_up"
      end
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_with_validation_failed_and_manual_activation
    with_settings :self_registration => 2, :openid => 1 do
      assert_no_difference 'ActionMailer::Base.deliveries.count' do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication_with_invalid_data
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/users/register/sign_up"
      end
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_with_validation_failed_and_auto_activation
    with_settings :self_registration => 3, :openid => 1 do
      assert_no_difference 'ActionMailer::Base.deliveries.count' do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication_with_invalid_data
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/users/register/sign_up"
      end
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_with_activation_by_email
    with_settings :self_registration => 1, :openid => 1 do
      assert_difference 'ActionMailer::Base.deliveries.count', 1 do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/users/sign_in"
        user = User.where(:email => 'abc@abc.com').first
        assert !user.active?
      end
    end
  end

  def test_login_by_openid_when_it_enabled_for_new_user_with_manual_activation
    with_settings :self_registration => 2, :openid => 1 do
      # account activation request for admin
      assert_difference 'ActionMailer::Base.deliveries.count', 1 do
        post "/users/sign_in", :user => { :identity_url => 'uid.someopenid.net' }
        assert_redirected_to "/users/auth/open_id?openid_url=uid.someopenid.net"

        mock_new_user_openid_authentication
        follow_redirect!
        assert_redirected_to "/users/auth/open_id/callback?openid_url=uid.someopenid.net"
        follow_redirect!
        assert_redirected_to "/users/sign_in"
        user = User.where(:email => 'abc@abc.com').first
        assert !user.active?
        assert user.registered?
      end
    end
  end

  def test_login_with_invalid_openid_provider
    OmniAuth.config.test_mode = false
    with_settings :openid => 1, :self_registration => 0 do
      post "/users/sign_in", :user => { :identity_url => 'http;//uid.someopenid.net' }
      follow_redirect!
      assert_redirected_to new_user_session_path
      assert_equal 'Could not authenticate you from OpenID because "Connection failed".', flash[:alert]
    end
  end

end
