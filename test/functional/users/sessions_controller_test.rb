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

class Users::SessionsControllerTest < ActionController::TestCase
  fixtures :users, :roles

  def setup
    @request.env["devise.mapping"] = Devise.mappings[:user]
    User.current = nil
  end

  def test_get_login
    get :new
    assert_response :success
    assert_template :new

    assert_select "input[name='user[login]']"
    assert_select "input[name='user[password]']"
  end

  def test_login_should_redirect_to_back_url_param
    # request.uri is "test.host" in test environment
    post :create, :user => { :login => 'jsmith', :password => 'jsmith' }, :back_url => 'http://test.host/issues/show/1'
    assert_redirected_to '/issues/show/1'
  end

  def test_login_should_not_redirect_to_another_host
    post :create, :user => { :login => 'jsmith', :password => 'jsmith' }, :back_url => 'http://test.foo/fake'
    assert_redirected_to '/my/page'
  end

  def test_login_with_wrong_password
    post :create, :user => { :login => 'admin', :password => 'bad' }
    assert_response :success
    assert_template :new

    assert_select 'div.flash.alert', :text => /Invalid login\/email or password/
    assert_select "input[name='user[login]']"
    assert_select "input[name='user[password]']"
    assert_select 'input[name=password][value]', 0
  end

  def test_login_should_reset_session
    @controller.expects(:expire_session_data_after_sign_in!).once

    post :create, :user => { :login => 'jsmith', :password => 'jsmith' }
    assert_response 302
  end

  def test_logout
    warden.expects(:reset_session!).once

    user = users(:users_002)
    sign_in user
    assert @request.session['warden.user.user.key'].include?([user.id])
    get :destroy
    assert_redirected_to '/'
    assert_nil @request.session['warden.user.user.key']
  end
end
