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

class Users::RegistrationsControllerTest < ActionController::TestCase
  fixtures :users, :roles

  def setup
    @request.env["devise.mapping"] = Devise.mappings[:user]
    User.current = nil
  end

  def test_get_register_with_registration_on
    with_settings :self_registration => '3' do
      get :new
      assert_response :success
      assert_template :new
      assert_not_nil assigns(:user)

      assert_tag 'input', :attributes => {:name => 'user[password]'}
      assert_tag 'input', :attributes => {:name => 'user[password_confirmation]'}
    end
  end

  def test_get_register_with_registration_off_should_redirect
    with_settings :self_registration => '0' do
      get :new
      assert_redirected_to '/users/sign_in'
    end
  end

  # See integration/account_test.rb for the full test
  def test_post_register_with_registration_on
    with_settings :self_registration => '3' do
      assert_difference 'User.count' do
        assert_no_difference 'ActionMailer::Base.deliveries.count' do
          post :create, :user => {
            :login => 'register',
            :password => 'test1234',
            :password_confirmation => 'test1234',
            :firstname => 'John',
            :lastname => 'Doe',
            :email => 'register@example.com'
          }
          assert_redirected_to '/my/account'
        end
      end
      user = User.first(:order => 'id DESC')
      assert_equal 'register', user.login
      assert_equal 'John', user.firstname
      assert_equal 'Doe', user.lastname
      assert_equal 'register@example.com', user.email
      assert user.valid_password?('test1234')
      assert user.active?
    end
  end

  def test_post_register_with_registration_on_and_confirmation_by_hand
    with_settings :self_registration => '2' do
      assert_difference 'User.count' do
        assert_difference 'ActionMailer::Base.deliveries.count', 1 do
          post :create, :user => {
            :login => 'register',
            :password => 'test1234',
            :password_confirmation => 'test1234',
            :firstname => 'John',
            :lastname => 'Doe',
            :email => 'register@example.com'
          }
          assert_redirected_to '/'
        end
      end
      user = User.first(:order => 'id DESC')
      assert_equal 'register', user.login
      assert_equal 'John', user.firstname
      assert_equal 'Doe', user.lastname
      assert_equal 'register@example.com', user.email
      assert user.valid_password?('test1234')
      assert user.registered?
      assert user.confirmed?
    end
  end

  def test_post_register_with_registration_on_and_confirmation_required
    with_settings :self_registration => '1' do
      assert_difference 'User.count' do
        assert_difference 'ActionMailer::Base.deliveries.count', 1 do
          post :create, :user => {
            :login => 'register',
            :password => 'test1234',
            :password_confirmation => 'test1234',
            :firstname => 'John',
            :lastname => 'Doe',
            :email => 'register@example.com'
          }
          assert_redirected_to '/'
        end
      end
      user = User.first(:order => 'id DESC')
      assert_equal 'register', user.login
      assert_equal 'John', user.firstname
      assert_equal 'Doe', user.lastname
      assert_equal 'register@example.com', user.email
      assert user.valid_password?('test1234')
      assert user.registered?
      assert !user.confirmed?
    end
  end

  def test_post_register_with_registration_off_should_redirect
    with_settings :self_registration => '0' do
      assert_no_difference 'User.count' do
        assert_no_difference 'ActionMailer::Base.deliveries.count' do
          post :create, :user => {
            :login => 'register',
            :password => 'test1234',
            :password_confirmation => 'test1234',
            :firstname => 'John',
            :lastname => 'Doe',
            :email => 'register@example.com'
          }
          assert_redirected_to '/users/sign_in'
        end
      end
    end
  end

  def test_cancel_account_with_allowed_to_delete_own_account
    with_settings :unsubscribe => '1' do
      assert_difference 'User.count', -1 do
        sign_in users(:users_002)
        delete :destroy
        assert_redirected_to '/'
        assert_equal 'Bye! Your account was successfully cancelled. We hope to see you again soon.', flash[:notice]
      end
    end
  end

  def test_cancel_account_without_allowed_to_delete_own_account
    with_settings :unsubscribe => '0' do
      assert_no_difference 'User.count' do
        sign_in users(:users_002)
        delete :destroy
        assert_redirected_to '/my/account'
        assert_nil flash[:notice]
      end
    end
  end
end
