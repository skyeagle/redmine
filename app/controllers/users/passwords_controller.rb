class Users::PasswordsController < Devise::PasswordsController
  skip_filter :require_no_authentication, :only => [:create]

  protected

  def after_sending_reset_password_instructions_path_for(resource_name)
    signed_in?(resource_name) ? back_url : new_session_path(resource_name)
  end

end
