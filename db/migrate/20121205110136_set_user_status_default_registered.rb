class SetUserStatusDefaultRegistered < ActiveRecord::Migration
  def up
    change_column :users, :status, :integer, :default => User::STATUS_REGISTERED, :null => false
  end

  def down
    change_column :users, :status, :integer, :default => User::STATUS_ACTIVE, :null => false
  end
end
