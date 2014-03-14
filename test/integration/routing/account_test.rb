# Redmine - project management software
# Copyright (C) 2006-2014  Jean-Philippe Lang
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

class RoutingAccountTest < ActionController::IntegrationTest
  def test_account
    assert_routing(
      { :method => 'get', :path => "/users/sign_in" },
      { :controller => 'users/sessions', :action => 'new' }
    )
    assert_routing(
      { :method => 'post', :path => "/users/sign_in" },
      { :controller => 'users/sessions', :action => 'create' }
    )
    assert_routing(
        { :method => 'delete', :path => "/users/sign_out" },
        { :controller => 'users/sessions', :action => 'destroy' }
    )
    assert_routing(
      { :method => 'get', :path => "/users/register/sign_up" },
      { :controller => 'users/registrations', :action => 'new' }
    )
    assert_routing(
      { :method => 'post', :path => "/users/register" },
      { :controller => 'users/registrations', :action => 'create' }
    )
    assert_routing(
      { :method => 'put', :path => "/users/register" },
      { :controller => 'users/registrations', :action => 'update' }
    )
    assert_routing(
      { :method => 'get', :path => "/users/password/new" },
      { :controller => 'users/passwords', :action => 'new' }
    )
    assert_routing(
      { :method => 'get', :path => "/users/password/edit" },
      { :controller => 'users/passwords', :action => 'edit' }
    )
    assert_routing(
      { :method => 'put', :path => "/users/password" },
      { :controller => 'users/passwords', :action => 'update' }
    )
    assert_routing(
      { :method => 'post', :path => "/users/password" },
      { :controller => 'users/passwords', :action => 'create' }
    )
    assert_routing(
      { :method => 'get', :path => "/users/confirmation/new" },
      { :controller => 'users/confirmations', :action => 'new' }
    )
    assert_routing(
      { :method => 'post', :path => "/users/confirmation" },
      { :controller => 'users/confirmations', :action => 'create' }
    )
    assert_routing(
      { :method => 'get', :path => "/users/confirmation" },
      { :controller => 'users/confirmations', :action => 'show' }
    )
  end
end
