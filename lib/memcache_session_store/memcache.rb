# AUTHOR: blink <blinketje@gmail.com>; blink#ruby-lang@irc.freenode.net

require 'rack/session/abstract/id'
require 'memcache'

module ActionDispatch
  module Session
    # Rack::Session::Memcache provides simple cookie based session management.
    # Session data is stored in memcached. The corresponding session key is
    # maintained in the cookie.
    # You may treat Session::Memcache as you would Session::Pool with the
    # following caveats.
    #
    # * Setting :expire_after to 0 would note to the Memcache server to hang
    #   onto the session data until it would drop it according to it's own
    #   specifications. However, the cookie sent to the client would expire
    #   immediately.
    #
    # Note that memcache does drop data before it may be listed to expire. For
    # a full description of behaviour, please see memcache's documentation.

    class SafeMemcacheSessionStore < AbstractStore
      attr_reader :mutex, :pool

      DEFAULT_OPTIONS = Rack::Session::Abstract::ID::DEFAULT_OPTIONS.merge \
        :namespace => 'rack:session',
        :memcache_server => 'localhost:11211'
      
      LOCK_EXPIRATION = 3.seconds
      MAX_LOCK_WAIT   = 3.seconds
      LOCK_RETRY_FREQ = 0.1

      def initialize(app, options={})
        super
        # Rails.logger.debug("******************* DEFAULT_OPTIONS : #{DEFAULT_OPTIONS.inspect}")
        # Rails.logger.debug("******************* init options: #{options.inspect}")
        
        @mutex = Mutex.new
        mserv = @default_options[:memcache_server]
        # mopts always evals to an empty hash... why is this in Rails 3.1?
        mopts = @default_options.reject{|k,v| !MemCache::DEFAULT_OPTIONS.include? k }
        # Rails.logger.debug("******************* default_options 1 : #{@default_options.inspect}")
        # Rails.logger.debug("******************* mopts options: #{mopts.inspect}")
        
        # this was in the 3.0.9 code and seems to make more sense than using an empty hash.
        @default_options = {
                  :namespace => 'rack:session',
                  :memcache_server => 'localhost:11211'
                }.merge(@default_options)
                
        # Rails.logger.debug("******************* default_options : #{@default_options.inspect}")

        @pool = options[:cache] || MemCache.new(mserv, @default_options)
        unless @pool.active? and @pool.servers.any?{|c| c.alive? }
          raise 'No memcache servers'
        end
      end

      def generate_sid
        loop do
          sid = super
          break sid if safe_new_sid(sid)
        end
      end

      def get_session(env, sid)
        Rails.logger.debug("************ getting session: #{sid.inspect}")
        with_lock(env, [nil, {}]) do
          unless sid and session = @pool.get(sid)
            sid, session = generate_sid, {}
            unless /^STORED/ =~ @pool.add(sid, session)
              raise "Session collision on '#{sid.inspect}'"
            end
          end
          [sid, session]
        end
      end

      # Rails 3.1 wants 4 params, Rails 3.0.9 wants 3 params. The default value should work with both.
      # def set_session(env, session_id, new_session, options)
      def set_session(env, session_id, new_session, options = {})
        Rails.logger.debug("******************* session_id: #{session_id.inspect}")
        Rails.logger.debug("******************* new_session: #{new_session.inspect}")
        Rails.logger.debug("******************* options: #{options.inspect}")
        Rails.logger.debug("******************* default options: #{DEFAULT_OPTIONS.inspect}")
        
        wait_until = Time.now + MAX_LOCK_WAIT
        success    = false
        
        while !success && Time.now < wait_until
          success = safe_write(env, session_id, new_session, options)
        
          # If the add fails, another process has the lock. Sleep for a bit then try again.
          unless success
            Rails.logger.debug("********* write failed. retrying in #{LOCK_RETRY_FREQ}s")
            sleep LOCK_RETRY_FREQ
          end
        end
      end

      def destroy_session(env, session_id, options)
        Rails.logger.debug("@@@@@@@@@@@@@@@@@@@@@@@ destroying session: #{session_id}")
        with_lock(env) do
          @pool.delete(session_id)
          generate_sid unless options[:drop]
        end
      end

      def with_lock(env, default=nil)
        @mutex.lock if env['rack.multithread']
        yield
      rescue MemCache::MemCacheError, Errno::ECONNREFUSED
        if $VERBOSE
          warn "#{self} is unable to find memcached server."
          warn $!.inspect
        end
        default
      ensure
        @mutex.unlock if @mutex.locked?
      end
      
      private
      
      def safe_write(env, session_id, new_session, options)
        # expiry = options[:expire_after]
        # expiry = expiry.nil? ? 0 : expiry + 1
        options = env['rack.session.options']
        expiry  = options[:expire_after] || 0
        Rails.logger.debug("******************* expiry: #{expiry}")
        
        # set a lock on the key lock_session_id using memcached's add operation.
        # If the add succeeds, make the write then delete the lock.
        locked = @pool.add "lock_#{session_id}", "locked", LOCK_EXPIRATION
        
        if /^STORED/ =~ locked
          # Rails.logger.debug("************** safe_write stored")
          
          with_lock(env, false) do
            # Rails.logger.debug("************* inside with_lock")
            @pool.set session_id, new_session, expiry
            session_id
          end
          
          # Rails.logger.debug("*******deleting")
          @pool.delete "lock_#{session_id}"
          
          return true
        else
          return false
        end
      end
      
      def safe_new_sid(session_id)
        key = "#{DEFAULT_OPTIONS[:namespace]}:#{session_id}"
        Rails.logger.debug("key: #{key.inspect}")
        avail = @pool.add key, "", 300
        
        Rails.logger.debug("avail: #{avail.inspect}")
        
        if /^STORED/ =~ avail
          Rails.logger.debug("session id is available")
          return session_id
        else
          return false
        end
      end
    end
  end
end
