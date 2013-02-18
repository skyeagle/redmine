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

class SessionStartTest < ActionController::TestCase
  tests Users::SessionsController

  fixtures :users

  def setup
    @request.env["devise.mapping"] = Devise.mappings[:user]
  end

  def test_login_should_set_session_timestamps
    user = User.find_by_login('jsmith')
    last_sign_in_at = user.last_sign_in_at

    post :create, :user => { :login => user.login, :password => user.login }
    assert_response 302
    assert_equal [user.id], request.session['warden.user.user.key'][1]
    user.reload
    assert_not_equal last_sign_in_at, user.last_sign_in_at
    assert_not_nil user.current_sign_in_at
    assert_not_nil user.current_sign_in_ip
    assert_not_nil user.last_sign_in_ip
  end
end
