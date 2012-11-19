class UpdateUserConfirmations < ActiveRecord::Migration
  def up
    User.where(:status => [1, 3]).find_each do |user|
      User.where(:id => user.id).update_all(:confirmed_at => user.created_on)
    end
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
