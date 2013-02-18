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

class MyControllerTest < ActionController::TestCase
  fixtures :users, :user_preferences, :roles, :projects, :members, :member_roles,
  :issues, :issue_statuses, :trackers, :enumerations, :custom_fields

  def setup
    sign_in users(:users_002)
  end

  def test_index
    get :index
    assert_response :success
    assert_template 'page'
  end

  def test_page
    get :page
    assert_response :success
    assert_template 'page'
  end

  def test_page_with_timelog_block
    preferences = User.find(2).pref
    preferences[:my_page_layout] = {'top' => ['timelog']}
    preferences.save!
    TimeEntry.create!(:user => User.find(2), :spent_on => Date.yesterday, :issue_id => 1, :hours => 2.5, :activity_id => 10)

    get :page
    assert_response :success
    assert_select 'tr.time-entry' do
      assert_select 'td.subject a[href=/issues/1]'
      assert_select 'td.hours', :text => '2.50'
    end
  end

  def test_page_with_all_blocks
    blocks = MyController::BLOCKS.keys
    preferences = User.find(2).pref
    preferences[:my_page_layout] = {'top' => blocks}
    preferences.save!

    get :page
    assert_response :success
    assert_select 'div.mypage-box', blocks.size
  end

  def test_my_account_should_show_editable_custom_fields
    get :account
    assert_response :success
    assert_template 'account'
    assert_equal User.find(2), assigns(:user)

    assert_tag :input, :attributes => { :name => 'user[custom_field_values][4]'}
  end

  def test_my_account_should_not_show_non_editable_custom_fields
    UserCustomField.find(4).update_attribute :editable, false

    get :account
    assert_response :success
    assert_template 'account'
    assert_equal User.find(2), assigns(:user)

    assert_no_tag :input, :attributes => { :name => 'user[custom_field_values][4]'}
  end

  def test_update_account
    post :account,
      :user => {
        :firstname => "Joe",
        :login => "root",
        :admin => 1,
        :group_ids => ['10'],
        :custom_field_values => {"4" => "0100562500"}
      }

    assert_redirected_to '/my/account'
    user = User.find(2)
    assert_equal user, assigns(:user)
    assert_equal "Joe", user.firstname
    assert_equal "jsmith", user.login
    assert_equal "0100562500", user.custom_value_for(4).value
    # ignored
    assert !user.admin?
    assert user.groups.empty?
  end

  def test_my_account_should_show_destroy_link
    get :account
    assert_select 'a[href=/users/register][data-method=delete][data-confirm~=sure]'
  end

  def test_page_layout
    get :page_layout
    assert_response :success
    assert_template 'page_layout'
  end

  def test_add_block
    post :add_block, :block => 'issuesreportedbyme'
    assert_redirected_to '/my/page_layout'
    assert User.find(2).pref[:my_page_layout]['top'].include?('issuesreportedbyme')
  end

  def test_add_invalid_block_should_redirect
    post :add_block, :block => 'invalid'
    assert_redirected_to '/my/page_layout'
  end

  def test_remove_block
    post :remove_block, :block => 'issuesassignedtome'
    assert_redirected_to '/my/page_layout'
    assert !User.find(2).pref[:my_page_layout].values.flatten.include?('issuesassignedtome')
  end

  def test_order_blocks
    xhr :post, :order_blocks, :group => 'left', 'blocks' => ['documents', 'calendar', 'latestnews']
    assert_response :success
    assert_equal ['documents', 'calendar', 'latestnews'], User.find(2).pref[:my_page_layout]['left']
  end

  def test_reset_rss_key_with_existing_key
    @previous_token_value = User.find(2).rss_key # Will generate one if it's missing
    post :reset_rss_key

    assert_not_equal @previous_token_value, User.find(2).rss_key
    assert User.find(2).rss_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_reset_rss_key_without_existing_key
    assert_nil User.find(2).rss_token
    post :reset_rss_key

    assert User.find(2).rss_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_reset_api_key_with_existing_key
    @previous_token_value = User.find(2).api_key # Will generate one if it's missing
    post :reset_api_key

    assert_not_equal @previous_token_value, User.find(2).api_key
    assert User.find(2).api_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_reset_api_key_without_existing_key
    assert_nil User.find(2).api_token
    post :reset_api_key

    assert User.find(2).api_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end
end
