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

require File.expand_path('../../test_helper', __FILE__)

class AdminTest < ActionController::IntegrationTest
  fixtures :projects, :trackers, :issue_statuses, :issues,
           :enumerations, :users, :issue_categories,
           :projects_trackers,
           :roles,
           :member_roles,
           :members,
           :enabled_modules,
           :workflows

  def test_add_user
    log_user("admin", "admin")
    get "/users/new"
    assert_response :success
    assert_template "users/new"
    post "/users",
         :user => { :login => "psmith", :firstname => "Paul",
                    :lastname => "Smith", :email => "psmith@somenet.foo",
                    :language => "en", :password => "psmith09",
                    :password_confirmation => "psmith09" }

    user = User.find_by_login("psmith")
    assert_kind_of User, user
    assert_redirected_to "/users/#{ user.id }/edit"

    logged_user = User.find_first_by_auth_conditions(:login => "psmith")
    assert_kind_of User, logged_user
    assert_equal "Paul", logged_user.firstname

    put "users/#{user.id}", :id => user.id, :user => { :status => User::STATUS_LOCKED }
    assert_redirected_to "/users/#{ user.id }/edit"
    locked_user = User.find_first_by_auth_conditions(:login => "psmith")
    assert_equal nil, locked_user
  end

  test "Add a user as an anonymous user should fail" do
    post '/users',
         :user => { :login => 'psmith', :firstname => 'Paul'},
         :password => "psmith09", :password_confirmation => "psmith09"
    assert_response :redirect
    assert_redirected_to "/users/sign_in?back_url=http%3A%2F%2Fwww.example.com%2Fusers"
  end
end
