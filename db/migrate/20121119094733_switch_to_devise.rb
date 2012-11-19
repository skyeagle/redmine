class SwitchToDevise < ActiveRecord::Migration
  def up
    remove_column :users, :auth_source_id

    rename_column :users, :mail, :email
    change_column :users, :email, :string, :limit => nil, :null => false, :default => ""

    rename_column :users, :hashed_password, :encrypted_password
    change_column :users, :encrypted_password, :string, :limit => nil, :null => false, :default => ""

    rename_column :users, :salt, :password_salt
    change_column :users, :password_salt, :string, :limit => nil

    ## Recoverable
    add_column :users, :reset_password_token, :string
    add_column :users, :reset_password_sent_at, :datetime

    ## Rememberable
    add_column :users, :remember_created_at, :datetime

    ## Trackable
    add_column :users, :sign_in_count, :integer, :default => 0
    add_column :users, :current_sign_in_at, :datetime
    rename_column :users, :last_login_on, :last_sign_in_at
    add_column :users, :current_sign_in_ip, :string
    add_column :users, :last_sign_in_ip, :string

    ## Confirmable
    add_column :users, :confirmation_token, :string
    add_column :users, :confirmed_at, :datetime
    add_column :users, :confirmation_sent_at, :datetime
    add_column :users, :unconfirmed_email, :string # Only if using reconfirmable

    ## Lockable
    # add_column :failed_attempts, :integer, :default => 0 # Only if lock strategy is :failed_attempts
    # add_column :unlock_token, :string # Only if unlock strategy is :email or :both
    # add_column :locked_at, :datetime

    ## Token authenticatable
    # add_column :authentication_token, :string



    drop_table :open_id_authentication_associations
    drop_table :open_id_authentication_nonces
  end

  def down
    create_table :open_id_authentication_associations, :force => true do |t|
      t.integer :issued, :lifetime
      t.string :handle, :assoc_type
      t.binary :server_url, :secret
    end

    create_table :open_id_authentication_nonces, :force => true do |t|
      t.integer :timestamp, :null => false
      t.string :server_url, :null => true
      t.string :salt, :null => false
    end

    # add_column :authentication_token, :string
    ## Token authenticatable

    # add_column :locked_at, :datetime
    # add_column :unlock_token, :string # Only if unlock strategy is :email or :both
    # add_column :failed_attempts, :integer, :default => 0 # Only if lock strategy is :failed_attempts
    ## Lockable

    remove_column :users, :unconfirmed_email # Only if using reconfirmable
    remove_column :users, :confirmation_sent_at
    remove_column :users, :confirmed_at
    remove_column :users, :confirmation_token
    ## Confirmable

    remove_column :users, :last_sign_in_ip
    remove_column :users, :current_sign_in_ip
    rename_column :users, :last_sign_in_at, :last_login_on
    remove_column :users, :current_sign_in_at
    remove_column :users, :sign_in_count
    ## Trackable

    remove_column :users, :remember_created_at
    ## Rememberable

    remove_column :users, :reset_password_sent_at
    remove_column :users, :reset_password_token
    ## Recoverable

    change_column :users, :password_salt, :string, :limit => 64
    rename_column :users, :password_salt, :salt

    change_column :users, :encrypted_password, :string, :limit => 40, :null => false, :default => ""
    rename_column :users, :encrypted_password, :hashed_password

    change_column :users, :email, :string, :limit => 60, :null => false, :default => ""
    rename_column :users, :email, :mail

    add_column :users, :auth_source_id, :integer
    add_index :users, :auth_source_id
  end
end
