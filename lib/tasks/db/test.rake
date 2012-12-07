Rake.application.remove_task 'db:test:prepare'

namespace :db do
  namespace :test do
    task :prepare do |t|
      # prevent Rake test to call task db:test:prepare
    end
  end
end
