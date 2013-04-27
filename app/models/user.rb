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

require "digest/sha1"

require "devise/encryptors/redmine_sha1"
require "devise/strategies/api_key_authenticatable"
require "devise/strategies/rss_key_authenticatable"

class User < Principal

  devise :database_authenticatable, :registerable, :confirmable,
    :recoverable, :rememberable, :trackable, :validatable, :encryptable,
    :api_key_authenticatable, :rss_key_authenticatable, :omniauthable

  # Setup accessible (or protected) attributes for your model
  include Redmine::SafeAttributes

  # Different ways of displaying/sorting users
  USER_FORMATS = {
    :firstname_lastname => {
        :string => '#{firstname} #{lastname}',
        :order => %w(firstname lastname id),
        :setting_order => 1
      },
    :firstname_lastinitial => {
        :string => '#{firstname} #{lastname.to_s.chars.first}.',
        :order => %w(firstname lastname id),
        :setting_order => 2
      },
    :firstname => {
        :string => '#{firstname}',
        :order => %w(firstname id),
        :setting_order => 3
      },
    :lastname_firstname => {
        :string => '#{lastname} #{firstname}',
        :order => %w(lastname firstname id),
        :setting_order => 4
      },
    :lastname_coma_firstname => {
        :string => '#{lastname}, #{firstname}',
        :order => %w(lastname firstname id),
        :setting_order => 5
      },
    :lastname => {
        :string => '#{lastname}',
        :order => %w(lastname id),
        :setting_order => 6
      },
    :username => {
        :string => '#{login}',
        :order => %w(login id),
        :setting_order => 7
      },
  }

  MAIL_NOTIFICATION_OPTIONS = [
    ['all', :label_user_mail_option_all],
    ['selected', :label_user_mail_option_selected],
    ['only_my_events', :label_user_mail_option_only_my_events],
    ['only_assigned', :label_user_mail_option_only_assigned],
    ['only_owner', :label_user_mail_option_only_owner],
    ['none', :label_user_mail_option_none]
  ]

  has_and_belongs_to_many :groups, :after_add => Proc.new {|user, group| group.user_added(user)},
                                   :after_remove => Proc.new {|user, group| group.user_removed(user)}
  has_many :changesets, :dependent => :nullify
  has_one :preference, :dependent => :destroy, :class_name => 'UserPreference'
  has_one :rss_token, :class_name => 'Token', :conditions => "action='feeds'"
  has_one :api_token, :class_name => 'Token', :conditions => "action='api'"

  scope :logged, lambda { where("#{User.table_name}.status <> #{STATUS_ANONYMOUS}") }
  scope :status, lambda {|arg| where(arg.blank? ? nil : {:status => arg.to_i}) }

  acts_as_customizable

  attr_accessor :generate_password
  attr_accessor :last_before_login_on
  # Prevents unauthorized assignments
  attr_protected :login, :admin, :encrypted_password, :password_salt

  LOGIN_LENGTH_LIMIT = 60

  validates_presence_of :login, :firstname, :lastname, :if => Proc.new { |user| !user.is_a?(AnonymousUser) }
  validates_uniqueness_of :login, :if => Proc.new { |user| user.login_changed? && user.login.present? }, :case_sensitive => false
  # Login must contain letters, numbers, underscores only
  validates_format_of :login, :with => /\A[a-z0-9_\-@\.]*\z/i
  validates_length_of :login, :maximum => LOGIN_LENGTH_LIMIT
  validates_length_of :firstname, :lastname, :maximum => 30
  validates_inclusion_of :mail_notification, :in => MAIL_NOTIFICATION_OPTIONS.collect(&:first), :allow_blank => true

  before_create :set_mail_notification
  before_validation :generate_password_if_needed
  before_destroy :remove_references_before_destroy

  scope :in_group, lambda {|group|
    group_id = group.is_a?(Group) ? group.id : group.to_i
    where("#{User.table_name}.id IN (SELECT gu.user_id FROM #{table_name_prefix}groups_users#{table_name_suffix} gu WHERE gu.group_id = ?)", group_id)
  }
  scope :not_in_group, lambda {|group|
    group_id = group.is_a?(Group) ? group.id : group.to_i
    where("#{User.table_name}.id NOT IN (SELECT gu.user_id FROM #{table_name_prefix}groups_users#{table_name_suffix} gu WHERE gu.group_id = ?)", group_id)
  }
  scope :sorted, lambda { order(*User.fields_for_order_statement)}

  def set_mail_notification
    self.mail_notification = Setting.default_notification_option if self.mail_notification.blank?
    true
  end


  alias :base_reload :reload
  def reload(*args)
    @name = nil
    @projects_by_role = nil
    @membership_by_project_id = nil
    base_reload(*args)
  end

  def self.new_with_session(params, session)
    super.tap do |user|
      if data = session['devise.open_id_data']
        data.delete_if{|k, v| v.blank? }
        data.each do |k, v|
          user.send :"#{k}=", v
        end
      end
    end
  end

  def self.find_for_open_id(access_token, signed_in_resource=nil)
    return if !access_token || Setting.openid != '1' || access_token.uid.blank?
    if user = User.where(:identity_url => access_token.uid).first
      user
    else
      return if Setting.self_registration == '0'
      data = access_token.info.with_indifferent_access
      user = User.create(:language => Setting.default_language) do |u|
        u.identity_url = access_token.uid if access_token.respond_to?(:uid)
        u.email = data['email'] if data['email'].present?
        u.password = u.password_confirmation = Devise.friendly_token[0,20]
        u.login = data['nickname'] if data['nickname'].present?
        if data['fullname'].present?
          u.firstname, u.lastname = data['fullname'].split(' ')
        elsif data['name'].present?
          u.firstname, u.lastname = data['name'].split(' ')
        end

        u.activate if Setting.self_registration == '3'

        # Skip confirmation by email when it should be manual by admin or automatic
        u.skip_confirmation! if [2,3].include?(Setting.self_registration.to_i)
      end

      if user && user.persisted?
        # Notify admin if manually activate by administrator
        Mailer.account_activation_request(user).deliver if Setting.self_registration == '2'
      end

      user
    end
  end

  def self.find_first_by_auth_conditions(params_conditions)
    conditions = params_conditions.dup
    if login = conditions.delete(:login)
      users = active.where(["login = :value", { :value => login }])
      if users.present? && user = users.detect {|u| u.login == login}
        user
      elsif user = active.where(["lower(login) = :value OR lower(email) = :value", { :value => login.downcase }]).first
        user
      end
    elsif conditions[:confirmation_token]
      where(conditions).first
    else
      active.where(conditions).first
    end
  end

  def self.name_formatter(formatter = nil)
    USER_FORMATS[formatter || Setting.user_format] || USER_FORMATS[:firstname_lastname]
  end

  # Returns an array of fields names than can be used to make an order statement for users
  # according to how user names are displayed
  # Examples:
  #
  #   User.fields_for_order_statement              => ['users.login', 'users.id']
  #   User.fields_for_order_statement('authors')   => ['authors.login', 'authors.id']
  def self.fields_for_order_statement(table=nil)
    table ||= table_name
    name_formatter[:order].map {|field| "#{table}.#{field}"}
  end

  # Return user's full name for display
  def name(formatter = nil)
    f = self.class.name_formatter(formatter)
    if formatter
      eval('"' + f[:string] + '"')
    else
      @name ||= eval('"' + f[:string] + '"')
    end
  end

  def active?
    self.status == STATUS_ACTIVE
  end

  def registered?
    self.status == STATUS_REGISTERED
  end

  def locked?
    self.status == STATUS_LOCKED
  end

  def activate
    self.status = STATUS_ACTIVE
  end

  def register
    self.status = STATUS_REGISTERED
  end

  def lock
    self.status = STATUS_LOCKED
  end

  def activate!
    confirm! unless confirmed?
    update_attribute(:status, STATUS_ACTIVE)
  end

  def register!
    update_attribute(:status, STATUS_REGISTERED)
  end

  def lock!
    update_attribute(:status, STATUS_LOCKED)
  end

  def active_for_authentication?
    active? && super
  end

  # Does the backend storage allow this user to change their password?
  def change_password_allowed?
    true
  end

  def generate_password?
    generate_password == '1' || generate_password == true
  end

  # Generate and set a random password on given length
  def random_password(length=40)
    chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
    chars -= %w(0 O 1 l)
    password = ''
    length.times {|i| password << chars[SecureRandom.random_number(chars.size)] }
    self.password = password
    self.password_confirmation = password
    self
  end

  def pref
    self.preference ||= UserPreference.new(:user => self)
  end

  def time_zone
    @time_zone ||= (self.pref.time_zone.blank? ? nil : ActiveSupport::TimeZone[self.pref.time_zone])
  end

  def wants_comments_in_reverse_order?
    self.pref[:comments_sorting] == 'desc'
  end

  # Return user's RSS key (a 40 chars long string), used to access feeds
  def rss_key
    if rss_token.nil?
      create_rss_token(:action => 'feeds')
    end
    rss_token.value
  end

  # Return user's API key (a 40 chars long string), used to access the API
  def api_key
    if api_token.nil?
      create_api_token(:action => 'api')
    end
    api_token.value
  end

  # Return an array of project ids for which the user has explicitly turned mail notifications on
  def notified_projects_ids
    @notified_projects_ids ||= memberships.select {|m| m.mail_notification?}.collect(&:project_id)
  end

  def notified_project_ids=(ids)
    Member.update_all("mail_notification = #{connection.quoted_false}", ['user_id = ?', id])
    Member.update_all("mail_notification = #{connection.quoted_true}", ['user_id = ? AND project_id IN (?)', id, ids]) if ids && !ids.empty?
    @notified_projects_ids = nil
    notified_projects_ids
  end

  def valid_notification_options
    self.class.valid_notification_options(self)
  end

  # Only users that belong to more than 1 project can select projects for which they are notified
  def self.valid_notification_options(user=nil)
    # Note that @user.membership.size would fail since AR ignores
    # :include association option when doing a count
    if user.nil? || user.memberships.length < 1
      MAIL_NOTIFICATION_OPTIONS.reject {|option| option.first == 'selected'}
    else
      MAIL_NOTIFICATION_OPTIONS
    end
  end

  # Find a user account by matching the exact login and then a case-insensitive
  # version.  Exact matches will be given priority.
  def self.find_by_login(login)
    if login.present?
      login = login.to_s
      # First look for an exact match
      user = where(:login => login).all.detect {|u| u.login == login}
      unless user
        # Fail over to case-insensitive if none was found
        user = where("LOWER(login) = ?", login.downcase).first
      end
      user
    end
  end

  def self.find_by_rss_key(key)
    Token.find_active_user('feeds', key)
  end

  def self.find_by_api_key(key)
    Token.find_active_user('api', key)
  end

  # Makes find_by_email case-insensitive
  def self.find_by_email(email)
    where(["LOWER(email) = ?", email.to_s.downcase]).first
  end
  class << self
    alias_method :find_by_mail, :find_by_email # backward compatibility for migrations
  end

  # Returns true if the default admin account can no longer be used
  def self.default_admin_account_changed?
    !User.active.find_by_login("admin").try(:valid_password?, "admin")
  end

  def to_s
    name
  end

  CSS_CLASS_BY_STATUS = {
    STATUS_ANONYMOUS  => 'anon',
    STATUS_ACTIVE     => 'active',
    STATUS_REGISTERED => 'registered',
    STATUS_LOCKED     => 'locked'
  }

  def css_classes
    "user #{CSS_CLASS_BY_STATUS[status]}"
  end

  # Returns the current day according to user's time zone
  def today
    if time_zone.nil?
      Date.today
    else
      Time.now.in_time_zone(time_zone).to_date
    end
  end

  # Returns the day of +time+ according to user's time zone
  def time_to_date(time)
    if time_zone.nil?
      time.to_date
    else
      time.in_time_zone(time_zone).to_date
    end
  end

  def logged?
    true
  end

  def anonymous?
    !logged?
  end

  # Returns user's membership for the given project
  # or nil if the user is not a member of project
  def membership(project)
    project_id = project.is_a?(Project) ? project.id : project

    @membership_by_project_id ||= Hash.new {|h, project_id|
      h[project_id] = memberships.where(:project_id => project_id).first
    }
    @membership_by_project_id[project_id]
  end

  # Return user's roles for project
  def roles_for_project(project)
    roles = []
    # No role on archived projects
    return roles if project.nil? || project.archived?
    if logged?
      # Find project membership
      membership = membership(project)
      if membership
        roles = membership.roles
      else
        @role_non_member ||= Role.non_member
        roles << @role_non_member
      end
    else
      @role_anonymous ||= Role.anonymous
      roles << @role_anonymous
    end
    roles
  end

  # Return true if the user is a member of project
  def member_of?(project)
    projects.to_a.include?(project)
  end

  # Returns a hash of user's projects grouped by roles
  def projects_by_role
    return @projects_by_role if @projects_by_role

    @projects_by_role = Hash.new([])
    memberships.each do |membership|
      if membership.project
        membership.roles.each do |role|
          @projects_by_role[role] = [] unless @projects_by_role.key?(role)
          @projects_by_role[role] << membership.project
        end
      end
    end
    @projects_by_role.each do |role, projects|
      projects.uniq!
    end

    @projects_by_role
  end

  # Returns true if user is arg or belongs to arg
  def is_or_belongs_to?(arg)
    if arg.is_a?(User)
      self == arg
    elsif arg.is_a?(Group)
      arg.users.include?(self)
    else
      false
    end
  end

  # Return true if the user is allowed to do the specified action on a specific context
  # Action can be:
  # * a parameter-like Hash (eg. :controller => 'projects', :action => 'edit')
  # * a permission Symbol (eg. :edit_project)
  # Context can be:
  # * a project : returns true if user is allowed to do the specified action on this project
  # * an array of projects : returns true if user is allowed on every project
  # * nil with options[:global] set : check if user has at least one role allowed for this action,
  #   or falls back to Non Member / Anonymous permissions depending if the user is logged
  def allowed_to?(action, context, options={}, &block)
    if context && context.is_a?(Project)
      return false unless context.allows_to?(action)
      # Admin users are authorized for anything else
      return true if admin?

      roles = roles_for_project(context)
      return false unless roles
      roles.any? {|role|
        (context.is_public? || role.member?) &&
        role.allowed_to?(action) &&
        (block_given? ? yield(role, self) : true)
      }
    elsif context && context.is_a?(Array)
      if context.empty?
        false
      else
        # Authorize if user is authorized on every element of the array
        context.map {|project| allowed_to?(action, project, options, &block)}.reduce(:&)
      end
    elsif options[:global]
      # Admin users are always authorized
      return true if admin?

      # authorize if user has at least one role that has this permission
      roles = memberships.collect {|m| m.roles}.flatten.uniq
      roles << (self.logged? ? Role.non_member : Role.anonymous)
      roles.any? {|role|
        role.allowed_to?(action) &&
        (block_given? ? yield(role, self) : true)
      }
    else
      false
    end
  end

  # Is the user allowed to do the specified action on any project?
  # See allowed_to? for the actions and valid options.
  def allowed_to_globally?(action, options, &block)
    allowed_to?(action, nil, options.reverse_merge(:global => true), &block)
  end

  # Returns true if the user is allowed to delete his own account
  def own_account_deletable?
    Setting.unsubscribe? &&
      (!admin? || User.active.where("admin = ? AND id <> ?", true, id).exists?)
  end

  safe_attributes 'login',
    'firstname',
    'lastname',
    'email',
    'password',
    'password_confirmation',
    'remember_me',
    'mail_notification',
    'language',
    'custom_field_values',
    'custom_fields',
    'identity_url'

  safe_attributes 'status',
    'auth_source_id',
    'generate_password',
    :if => lambda {|user, current_user| current_user.admin?}

  safe_attributes 'group_ids',
    :if => lambda {|user, current_user| current_user.admin? && !user.new_record?}

  # Utility method to help check if a user should be notified about an
  # event.
  #
  # TODO: only supports Issue events currently
  def notify_about?(object)
    if mail_notification == 'all'
      true
    elsif mail_notification.blank? || mail_notification == 'none'
      false
    else
      case object
      when Issue
        case mail_notification
        when 'selected', 'only_my_events'
          # user receives notifications for created/assigned issues on unselected projects
          object.author == self || is_or_belongs_to?(object.assigned_to) || is_or_belongs_to?(object.assigned_to_was)
        when 'only_assigned'
          is_or_belongs_to?(object.assigned_to) || is_or_belongs_to?(object.assigned_to_was)
        when 'only_owner'
          object.author == self
        end
      when News
        # always send to project members except when mail_notification is set to 'none'
        true
      end
    end
  end

  def self.current=(user)
    Thread.current[:current_user] = user
  end

  def self.current
    Thread.current[:current_user] ||= User.anonymous
  end

  # Returns the anonymous user.  If the anonymous user does not exist, it is created.  There can be only
  # one anonymous user per database.
  def self.anonymous
    anonymous_user = AnonymousUser.first
    if anonymous_user.nil?
      anonymous_user = AnonymousUser.create(:lastname => 'Anonymous', :firstname => '', :email => '', :login => '', :status => 0)
      raise 'Unable to create the anonymous user.' if anonymous_user.new_record?
    end
    anonymous_user
  end

  # Salts all existing unsalted passwords
  # It changes password storage scheme from SHA1(password) to SHA1(salt + SHA1(password))
  # This method is used in the SaltPasswords migration and is to be kept as is
  def self.salt_unsalted_passwords!
    salt_field, password_field = \
      if ActiveRecord::Base.connection.column_exists?(:users, :encrypted_password)
        [:password_salt, :encrypted_password]
      else
        [:salt, :hashed_password]
      end

    transaction do
      User.where("#{salt_field} IS NULL OR #{salt_field} = ''").find_each do |user|
        next if user.read_attribute(password_field).blank?
        salt = encryptor_class.salt
        hashed_password = encryptor_class.hash_password("#{salt}#{user.read_attribute(password_field)}")
        User.where(:id => user.id).update_all(salt_field => salt, password_field => hashed_password)
      end
    end
  end

  private

  def generate_password_if_needed
    if generate_password?
      length = [Setting.password_min_length.to_i + 2, 10].max
      random_password(length)
    end
  end

  # Removes references that are not handled by associations
  # Things that are not deleted are reassociated with the anonymous user
  def remove_references_before_destroy
    return if self.id.nil?

    substitute = User.anonymous
    Attachment.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    Comment.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    Issue.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    Issue.update_all 'assigned_to_id = NULL', ['assigned_to_id = ?', id]
    Journal.update_all ['user_id = ?', substitute.id], ['user_id = ?', id]
    JournalDetail.update_all ['old_value = ?', substitute.id.to_s], ["property = 'attr' AND prop_key = 'assigned_to_id' AND old_value = ?", id.to_s]
    JournalDetail.update_all ['value = ?', substitute.id.to_s], ["property = 'attr' AND prop_key = 'assigned_to_id' AND value = ?", id.to_s]
    Message.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    News.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    # Remove private queries and keep public ones
    ::Query.delete_all ['user_id = ? AND is_public = ?', id, false]
    ::Query.update_all ['user_id = ?', substitute.id], ['user_id = ?', id]
    TimeEntry.update_all ['user_id = ?', substitute.id], ['user_id = ?', id]
    Token.delete_all ['user_id = ?', id]
    Watcher.delete_all ['user_id = ?', id]
    WikiContent.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
    WikiContent::Version.update_all ['author_id = ?', substitute.id], ['author_id = ?', id]
  end

  alias_attribute :last_login_on, :last_sign_in_at
end

class AnonymousUser < User
  validate :validate_anonymous_uniqueness, :on => :create

  def validate_anonymous_uniqueness
    # There should be only one AnonymousUser in the database
    errors.add :base, 'An anonymous user already exists.' if AnonymousUser.exists?
  end

  def available_custom_fields
    []
  end

  # Overrides a few properties
  def logged?; false end
  def admin; false end
  def name(*args); I18n.t(:label_user_anonymous) end
  def email; nil end
  def time_zone; nil end
  def rss_key; nil end

  def pref
    UserPreference.new(:user => self)
  end

  def member_of?(project)
    false
  end

  # Anonymous user can not be destroyed
  def destroy
    false
  end

   def password_required?
     false
   end

   def email_required?
     false
   end

end
