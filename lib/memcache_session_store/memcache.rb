# AUTHOR: blink <blinketje@gmail.com>; blink#ruby-lang@irc.freenode.net

# require 'rack/session/abstract/id'
require 'action_dispatch/middleware/session/abstract_store'
require 'memcache'
require 'cgi'

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

      DEFAULT_OPTIONS = ActionDispatch::Session::AbstractStore::DEFAULT_OPTIONS.merge \
        :namespace => 'rack:session',
        :memcache_server => 'localhost:11211'
      
      LOCK_EXPIRATION = 3
      MAX_LOCK_WAIT   = 3
      LOCK_RETRY_FREQ = 0.1

      def initialize(app, options={})
        super
        # Rails.logger.debug("******************* DEFAULT_OPTIONS : #{DEFAULT_OPTIONS.inspect}")
        # Rails.logger.debug("******************* init options: #{options.inspect}")
        
        @mutex = Mutex.new
        
        @default_options = {
                  :namespace => 'rack:session',
                  :memcache_server => 'localhost:11211'
                }.merge(@default_options)
                
        # Rails.logger.debug("******************* default_options : #{@default_options.inspect}")

        @pool = options[:cache] || MemCache.new(@default_options[:memcache_server], @default_options)
        unless @pool.active? and @pool.servers.any?{|c| c.alive? }
          raise 'No memcache servers'
        end
      end
      
      private

      def generate_sid
        # loop do
        #   sid = super
        #   # break sid if safe_new_sid(sid)
        #   break sid unless @pool.get(sid)
        # end
        
        sid = super
        num_tries = 0
        
        while num_tries < 20 && !safe_new_sid(sid)
          Rails.logger.debug("That sid was taken; trying to get another one...")
          sid = super
          num_tries += 1
        end
        
        raise "Couldn't generate a unique session ID!" unless sid
        
        return sid
      end

      def get_session(env, sid)
        # Rails.logger.debug("||||||||||||||||||||||||||")
        # Rails.logger.debug("||||||||||||||||||||||||||")
        # Rails.logger.debug("||||||||||||||||||||||||||")
        # Rails.logger.debug("||||||||||||||||||||||||||")
        # Rails.logger.debug("|||||||||| env: #{env["rack.request.query_hash"][:sid].inspect}")
        # paramsid = get_sid_from_params(env["QUERY_STRING"])
        # sid = get_sid_from_params(env["QUERY_STRING"]) || sid
        params_sid = env["rack.request.query_hash"][:sid] rescue nil
        sid = params_sid || sid
        Rails.logger.debug("************ getting session: #{sid.inspect} ... #{env.inspect}")
        with_lock(env, [nil, {}]) do
          unless sid and session = @pool.get(sid)
            # sid, session = generate_sid, {}
            sid = generate_sid unless sid
            session = {}
            Rails.logger.debug("==================== new sid: #{sid.inspect}")
            # unless /^STORED/ =~ @pool.add(sid, session)
              # raise "Session collision on '#{sid.inspect}'"
            # else
              # Rails.logger.debug("***** get session else sid: #{sid.inspect}")
            # end
          end
          
          Rails.logger.debug("==================== sid: #{sid.inspect}")
          [sid, session]
        end
      end

      # Rails 3.1 wants 4 params, Rails 3.0.9 wants 3 params. The default value should work with both.
      # def set_session(env, session_id, new_session, options)
      def set_session(env, session_id, new_session, options = {})
        options = env['rack.session.options']
        
        # Rails.logger.debug("******************* session_id: #{session_id.inspect} new_session: #{new_session.inspect}")
        # Rails.logger.debug("******************* options: #{options.inspect}")
        # Rails.logger.debug("******************* default options: #{DEFAULT_OPTIONS.inspect}")
        
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
        
        Rails.logger.debug("********** set_session success: #{success.inspect}")
        
        return success
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
      
      def safe_write(env, session_id, new_session, options)
        expiry = options[:expire_after] || 0
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
          
          return session_id
        else
          Rails.logger.debug("locked isnt STORED, its: #{locked.inspect}")
          return false
        end
      end
      
      def safe_new_sid(session_id)
        key = "#{DEFAULT_OPTIONS[:namespace]}:#{session_id}"
        avail = @pool.add key, "", 300
        
        if /^STORED/ =~ avail
          return session_id
        else
          return false
        end
      end
      
      # def get_sid_from_params(params)        
      #         # sid = CGI::parse(params)['sid'] #rescue nil
      #         sid = CGI::parse(params)
      #         Rails.logger.debug("******    sid: #{sid.inspect}")
      #         
      #         return sid
      #         # @pool.get(sid) ? sid : nil
      #       end
    end
  end
end
