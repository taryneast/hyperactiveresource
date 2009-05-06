# Raised by ActiveRecord::Base.save! and ActiveRecord::Base.create! methods when record cannot be
# saved because record is invalid.
class AbstractRecordError < StandardError; end

# Raised by ActiveRecord::Base.save! and ActiveRecord::Base.create! methods when record cannot be
# saved because record is invalid.
class ResourceNotSaved < AbstractRecordError; end

class HyperactiveResource < ActiveResource::Base
  # Quick overloading of the ActiveRecord-style naming function for the
  # model in error messages.  This will be updated when associations are
  # complete
  def self.human_name(options = {})
    self.name.humanize
  end
  # Quick overloading of the ActvieRecord-style naming functions for
  # attributes in error messages.
  # This will be updated when associations are complete
  def self.human_attribute_name(attribute_key_name, options = {})
    attribute_key_name.humanize
  end

  # load the files here so we can test the code independantly of a rails
  # setup.
  require "active_record"
  # need to use load because require will kill active_record's own require
  # of the validatios module
  load "active_record/validations.rb"


  # Active\Resource's errors object is only a random selection of
  # ActiveRecord's error methods - and most of them are just copies of older
  # versions (eg before they added il8n)
  # So why not just inherit the attributes and add in the *only*
  # ActiveResource method that actually differs?
  class Errors < ActiveRecord::Errors
    
    def initialize(base) # :nodoc:
      #p "initializing ActiveResource::Errors: methods available: #{methods.sort.inspect}"
      @base, @errors = base, {}
    end

  # Edited from ActiveRecord as we don't yet fully support 
  # associations
    def generate_message(attribute, message = :invalid, options = {})

      message, options[:default] = options[:default], message if options[:default].is_a?(Symbol)

      defaults = [@base.class].map do |klass|
        [ :"models.#{klass.name.underscore}.attributes.#{attribute}.#{message}", 
          :"models.#{klass.name.underscore}.#{message}" ]
      end
      
      defaults << options.delete(:default)
      defaults = defaults.compact.flatten << :"messages.#{message}"

      key = defaults.shift
      value = @base.respond_to?(attribute) ? @base.send(attribute) : nil

      options = { :default => defaults,
        :model => @base.class.human_name,
        :attribute => @base.class.human_attribute_name(attribute.to_s),
        :value => value,
        :scope => [:activerecord, :errors]
      }.merge(options)

      I18n.translate(key, options)
    end

    
    # Grabs errors from the XML response.
    def from_xml(xml)
      clear
      humanized_attributes = @base.attributes.keys.inject({}) { |h, attr_name| h.update(attr_name.humanize => attr_name) }
      messages = Array.wrap(Hash.from_xml(xml)['errors']['error']) rescue []
      messages.each do |message|
        attr_message = humanized_attributes.keys.detect do |attr_name|
          if message[0, attr_name.size + 1] == "#{attr_name} "
            add humanized_attributes[attr_name], message[(attr_name.size + 1)..-1]
          end
        end
        
        add_to_base message if attr_message.nil?
      end
    end
  end


  # make validations work just like ActiveRecord by pulling them in directly
  extend ActiveRecord::Validations::ClassMethods
  # create callbacks for validate/validate_on_create/validate_on_update
  # Note: pull them from ActiveRecord's list in case they decide to update
  # the list...
  include ActiveSupport::Callbacks
  self.define_callbacks *ActiveRecord::Validations::VALIDATIONS
  # Add the standard list of ActiveRecord callbacks (for good measure).
  # Calling this here means we can override these with our own versions
  # below.
  self.define_callbacks *ActiveRecord::Base::CALLBACKS
  
  # make sure attributes of ARES has indifferent_access
  def initialize(attributes = {})
    @attributes     = {}.with_indifferent_access
    @prefix_options = {}
    load(attributes)
  end                             
  
  #This is required to make it behave like ActiveRecord
  def attributes=(new_attributes)    
    attributes.update(new_attributes)
  end
   
  def to_xml(options = {})
    # fix for rails bug 2521 (auto dasherizing when no field passed in)
    # Remove this when Rails has been fixed.
    [:dasherize, :camelize].each do |f|
      options[f] = (options.has_key?(f) && options[f] == true)
    end
    super(options)
  end


  # validates_uniqeuness_of has to pull data out of the remote webserver
  # to test, so it has to be rewritten for ARes-style stuff.
  # Currently assumes that you know what you're doing - ie no check for
  # whether the given model actually *has* the given attribute.
  # Just checks if a record already exists with the given value for the
  # given column.
  def self.validates_uniqueness_of(*attr_names)
    configuration = {}
    configuration.update(attr_names.extract_options!)

    validates_each(attr_names,configuration) do |record, attr_name, value|    
      # skip if we allow nil and value is nil
      if (!configuration.has_key?(:allow_nil) || (configuration[:allow_nil] && !value.blank?))
        # TODO: make the below work
        #record.errors.add(attr_name, :taken, :default => configuration[:message], :value => value) if self.count(:conditions => {attr_name.to_s => value}) > 0
        # Currently find just fetches *every* record and we then have to
        # hand-filter it... :P

        match_set = self.find(:all, :conditions => { attr_name => value})
        # arrayify if we returned a single item
        match_set = [match_set] unless match_set.respond_to?(:[])
        match_set.compact!
        if !match_set.blank? # only bother if we found something
          # there are two cases where there's no error.
          # Firstly, if we found none matching at all
          # Secondly, if we found one - but it's really the current record...
          #   which will only occur if the ids match
          # So we need to count the number of records returned that have the
          # attribute we've passed in... but don't have our id.
          record.errors.add the_attr, "has already been taken. Please choose another" unless 0 == match_set.count {|rec| (value == rec.send(attr_name)) && (record.id && rec.id != record.id) }
        end
      end
    end
  end


  # currently, ActiveResource doesn't handle a 404 on a destroy_all very
  # nicely... 
  # Returns true if it destroyed them all successfully.
  # Returns nil if it didn't find any.
  #
  # Note: make sure the remote API does not just redirect on delete (as per
  # somne standard Rails pre-generated code)... make sure it handles the xml
  # format nicely sending either a 200 or a 404 where appropriate
  def self.destroy_all(conditions = nil)
    begin
      matches = find(:all, :conditions => conditions)
      unless matches.blank?
        matches = [matches] unless matches.respond_to?(:[]) # arrayify
        matches.each { |object| object.destroy  }
      end
    rescue ActiveResource::ResourceNotFound
      # we want to do nothing here... basically it just found nothing
      # matching the given conditions
      return nil
    end
    true
  end
  # unlike ActiveRecord... there's no easy way to just delete without
  # instantiating, so just alias the above.
  def self.delete_all(conds = nil)
    self.destroy_all(conds)
  end

     
  # Saves the model
  #
  # This will save remotely after making sure there are no local errors
  # returns false if saving fails
  def save(perform_validations = true)
    before_save    
    successful = (perform_validations ? super() : save_without_validation)
    after_save if successful          
    successful
  end    
    
  # Saves the model
  #
  # This will save remotely after making sure there are no local errors
  # Throws RecordNotSaved if saving fails
  def save!(perform_validations = true)
    save(perform_validations) || raise(ResourceNotSaved)
  end 
 
  # runs +validate+ and returns true if no errors were added otherwise false.
  def valid? 
    errors.clear

    run_callbacks(:validate)
    validate

    if new_record?
      run_callbacks(:validate_on_create)
      validate_on_create
    else
      run_callbacks(:validate_on_update)
      validate_on_update
    end

    # we're valid if we found no errors
    errors.empty?
  end
  
  # Returns the Errors object that holds all information about attribute error messages.
  def errors
    @errors ||= Errors.new(self)
  end

  alias :new_record? :new?

  def respond_to?(method, include_private = false)
    attribute_getter?(method) || attribute_setter?(method) || super
  end
  
  # copy/pasted from http://dev.rubyonrails.org/attachment/ticket/7308/reworked_activeresource_update_attributes_patch.diff
  #
  # Updates a single attribute and requests that the resource be saved. 
  # 
  # Note: Unlike ActiveRecord::Base.update_attribute, this method <b>is</b> subject to normal validation 
  # routines as an update sends the whole body of the resource in the request.  (See Validations). 
  # As such, this method is equivalent to calling update_attributes with a single attribute/value pair. 
  # 
  # Note: Also unlike ActiveRecord::Base, ActiveResource currently uses string versions of attribute 
  # names, so use <tt>update_attribute("name", "ryan")</tt> <em>instead of</em> <tt>update_attribute(:name, "ryan")</tt>. 
  # 
  # If the saving fails because of a connection or remote service error, an exception will be raised.  If saving 
  # fails because the resource is invalid then <tt>false</tt> will be returned. 
  #     
  def update_attribute(name, value) 
    update_attributes(name => value)
  end 
 
  # Updates this resource withe all the attributes from the passed-in Hash and requests that 
  # the record be saved. 
  # 
  # If the saving fails because of a connection or remote service error, an exception will be raised.  If saving 
  # fails because the resource is invalid then <tt>false</tt> will be returned. 
  # 
  # Note: Though this request can be made with a partial set of the resource's attributes, the full body 
  # of the request will still be sent in the save request to the remote service.  Also note that 
  # ActiveResource currently uses string versions of attribute 
  # names, so use <tt>update_attributes("name" => "ryan")</tt> <em>instead of</em> <tt>update_attribute(:name => "ryan")</tt>. 
  #     
  def update_attributes(attributes) 
    load(attributes) && save 
  end

  #  Works the same as +update_attributes+ but uses +save!+ rather than
  #  +save+
  #  Thus it will throw an exception if the save fails.
  def update_attributes!(attributes)
    load(attributes) || raise(ResourceNotSaved)
    save! 
  end
  




  protected   ##########################################################

    # used when somebody overloads the "attribute=" method and then wants to
    # save the value into attributes
    def write_attribute(key, value)
      attributes[key.to_s] = value
    end


    # overwrite the encoding function to massage our associations attributes
    # into a form that can be encoded nicely.
    def encode(opts = {})
      # don't bother unless we have some
      return super(opts) if self.belong_tos.blank?

      massaged_attributes = attributes.dup
      
      # Massage patient.id into patient_id (for every belongs_to)
      massaged_attributes.each do |key, value|
        if self.belong_tos.include? key.to_sym
          massaged_attributes["#{key}_id"] = value.id unless value.blank?
          massaged_attributes.delete(key)       
        elsif key.to_s =~ /^.*_ids$/
          massaged_attributes.delete(key)        
        end
      end
      
      # Skip the things in the skip list
      massaged_attributes.delete_if {|key,value| skip_to_xml_for.include? key.to_sym }
      # the following is a copy of ARes's encode - but with our new attributes
      # It may need to be updated if we want to stay in line with ARes. :P
      case self.class.format
        when ActiveResource::Formats[:xml]
          self.class.format.encode(massaged_attributes, {:root => self.class.element_name}.merge(opts))
        else
          self.class.format.encode(massaged_attributes, opts)
      end
    end
    
    def save_nested
      return if nested_resources.blank?
      @saved_nested_resources = {}
      nested_resources.each do |nested_resource_name|
        resources = attributes[nested_resource_name.to_s.pluralize] 
        resources ||= send(nested_resource_name.to_s.pluralize)
        unless resources.nil?
          resources.each do |resource|
            @saved_nested_resources[nested_resource_name] = []
            #We need to set a reference from this nested resource back to the parent  

            fk = self.respond_to?("#{nested_resource_name}_options") ? self.send("#{nested_resource_name}_options")[:foreign_key]  : "#{self.class.name.underscore}_id"
            resource.send("#{fk}=", self.id)
            @saved_nested_resources[nested_resource_name] << resource if resource.save
          end
        end
      end
    end
    
    # Update the resource on the remote service.
    def update
      connection.put(element_path(prefix_options), encode, self.class.headers).tap do |response|
        save_nested
        load_attributes_from_response(response)
        merge_saved_nested_resources_into_attributes
      end
      self
    end

    # Create (i.e., save to the remote service) the new resource.
    def create
      connection.post(collection_path, encode, self.class.headers).tap do |response|
        self.id = id_from_response(response) 
        save_nested
        load_attributes_from_response(response)
        merge_saved_nested_resources_into_attributes
      end
      self
    end  
    
    def merge_saved_nested_resources_into_attributes
      return if nested_resources.blank?
      @saved_nested_resources.each_key do |nested_resource_name|
        attr_name = nested_resource_name.to_s.pluralize
        resource_list_before_merge = attributes[attr_name] || []
        attributes[attr_name] = resource_list_before_merge - @saved_nested_resources[nested_resource_name]
        attributes[attr_name] +=  @saved_nested_resources[nested_resource_name]
      end
      @saved_nested_resources = []
    end
    
    def id_from_response(response)
      # response['Location'][/\/([^\/]*?)(\.\w+)?$/, 1] if response['Location'] 
      Hash.from_xml(response.body).values[0]["id"]
    end            
    
    def after_save
    end
    
    def before_save
      before_save_or_validate
    end
    
    def before_validate
      before_save_or_validate
    end
    
    #TODO I don't like the way this works. If you override validate you have to remember to call before_validate or super..
    def validate
      before_validate
    end

    # empty functions to be overloaded int he class if necessary.
    def validate_on_update
    end
    def validate_on_create
    end
     
    def before_save_or_validate
      #Do nothing
    end     
    
    class_inheritable_accessor :has_manys
    class_inheritable_accessor :nested_has_manys
    class_inheritable_accessor :has_ones
    class_inheritable_accessor :nested_has_ones
    class_inheritable_accessor :belong_tos
    class_inheritable_accessor :columns
    class_inheritable_accessor :skip_to_xml_for
    class_inheritable_accessor :nested_resources
    
    self.nested_resources = []
    self.has_manys = []
    self.nested_has_manys = []
    self.has_ones = []
    self.nested_has_ones = []
    self.belong_tos = []

    self.columns = []
    self.skip_to_xml_for = []

    #These possibly don't work! :)
    def self.belongs_to( names )
      raise ArgumentError if names.blank?
      names = [names] unless names.respond_to?(:[]) # arrayify
      self.belong_tos << names
    end
      
    def self.has_many( names )
      raise ArgumentError if names.blank?
      names = [names] unless names.respond_to?(:[]) # arrayify
      self.has_manys << names
    end
    
    def self.column( names )
      raise ArgumentError if names.blank?
      names = [names] unless names.respond_to?(:[]) # arrayify
      self.columns << names
    end 
        
  #  When you call any of these dynamically inferred methods 
  #  the first call sets it so it's no longer dynamic for subsequent calls
  #  Ie. If there is residencies but no residency_ids
  #  then when you first call residency_ids it'll pull the residency ids into the residency_ids..
  #  But future changes aren't kept in sync (like ActiveRecord.. mostly)
    def method_missing(name, *args)
      return super if attributes.keys.include? name.to_s         
      
      case name
      when *self.columns
        return column_getter_method_missing(name)
      when *self.belong_tos
        return belong_to_getter_method_missing(name)
      when *self.belong_to_ids
        return belong_to_id_getter_method_missing(name)
      when *self.has_manys
        return has_many_getter_method_missing(name)
      when *self.has_many_ids
        return has_many_ids_getter_method_missing(name)
      when *self.has_ones
        return has_one_getter_method_missing(name)      
      end                                     

      # hkau
      # something like this to support "nested xxxx="
      #
      # if name.to_s.ends_with?('=')
      #   setter_name = name.to_s[0..(name.to_s.length-2)]
      #   puts "---------- setter_name #{setter_name}"
      #   if nested_has_ones.include?(setter_name.to_sym)
      #     return send "#{setter_name}_id=", args[0].id
      #   end
      # end

      super
    end
    
    #Used by method_missing & load to infer setter & getter names from association names
    def has_many_ids    
      self.has_manys.map { |hm| "#{hm.to_s.singularize}_ids".to_sym }
    end
    
    #Used by method_missing & load to infer setter & getter names from association names
    def belong_to_ids
      self.belong_tos.map { |bt| "#{bt}_id".to_sym }
    end
    
    #Calls to column getter when there is no attribute for it, nor a previous set called it will return nil rather than freak out
    def column_getter_method_missing( name )
      self.call_setter(name, nil)
    end
    
    #Getter for a belong_to relationship checks if the _id exists and dynamically finds the object
    def belong_to_getter_method_missing( name )
      #If there is a blah_id but not blah get it via a find
      association_id = self.send("#{name.to_s.underscore}_id")
      (association_id.nil? or ( association_id.respond_to? :empty? and association_id.empty? ) ) ? 
        nil : call_setter(name, name.to_s.camelize.constantize.send(:find, association_id ) )
    end
    
    #Getter for a belong_to's id will return the object.id if it exists
    def belong_to_id_getter_method_missing( name )
      #The assumption is that this will always be called with a name that ends in _id   
      association_name = remove_id name
      unless attributes[association_name].nil? #If there is the obj itself rather than the blah_id
        call_setter( name, self.send(association_name).id ) #Use the blah.id for blah_id
      else  
        column_getter_method_missing( name ) #call_setter( name, nil ) #Just like a column
      end
    end
    
    #If there is _ids, but not objects array the method missing for has_many will get each object via id. Otherwise it will return
    #an empty array (like active
    def has_many_getter_method_missing( name )
      association_ids = self.send("#{name.to_s.singularize.underscore}_ids")
      if association_ids.nil? or association_ids.empty?
        call_setter(name, []) #return
      else
        #If we have blah_ids and no blahs, get them all via finds
        associated_models = association_ids.collect do |associated_id| 
          name.to_s.singularize.camelize.constantize.send(:find, associated_id)
        end
        call_setter(name, associated_models) #return
      end
    end
    
    def has_many_ids_getter_method_missing( name )
      association_name = remove_id(name).pluralize #(residency_ids => residencies)
      unless attributes[association_name].nil?
        call_setter(name, self.send(association_name).collect(&:id) )
      else
        call_setter(name, [])
      end
    end
    
    def has_one_getter_method_missing( name )
      self.new? ? nil : 
        call_setter( name, name.to_s.camelize.constantize.send("find_by_#{self.class.name.underscore}_id", self.id) )
    end

    #Convenience method used by the method_missing methods
    def call_setter( name, value )
      # puts "****************** call_setter( #{name}, #{value} )"
      self.send( "#{name}=", value )
    end
    
    #Chops the _id off the end of a method name to be used in method_missing
    def remove_id( name_with_id )
      name_with_id.to_s.gsub(/_ids?$/,'')
    end
    
    #There are lots of differences between active_resource's initializer and active_record's
    #ARec lets you pass a block 
    #Arec doesn't clone
    #Arec calls blah= on everything that's passed in.
    #Arec will turn a "1" into a 1 if it's in an ID column (or any integer for that matter)
    #This is a copy of the method out of ActiveResource::Base modified
    def load(attributes)
      raise ArgumentError, "expected an attributes Hash, got #{attributes.inspect}" unless attributes.is_a?(Hash)
      @prefix_options, attributes = split_options(attributes)
      attributes.each do |key, value|      
        @attributes[key.to_s] =
          case value
            when Array
              #BEGIN ADDITION TO AR::BASE
              load_array(key, value)
              #END ADDITION              
            when Hash
              resource = find_or_create_resource_for(key)
              resource.new(value)
            else
              #BEGIN ADDITION TO AR::BASE
              convert_to_i_if_id_field(key, value)
              #WAS: value #.dup rescue value #REMOVED FROM AR:BASE
              #END ADDITION                                                  
            end
        #BEGIN ADDITION TO AR::BASE
        call_attribute_setter(key, value)
        #END ADDITION
      end
      #BEGIN ADDITION TO AR::BASE
      result = yield self if block_given?
      #END ADDITION
      result || self
    end
    
    #Called by overriden load
    def load_array( key, value )
      if self.has_many_ids.include? key
        #This means someone has set blah_ids = [1,2,3]
        #Instead of being retarded like ActiveResource normally is,
        #Let's turn this into "1,2,3"
        value.join(',')
      else
        resource = find_or_create_resource_for_collection(key)
        value.map { |attrs| resource.new(attrs) }
      end
    end
      
    #Called by overriden load
    def convert_to_i_if_id_field( key, value )
      #This might be an id of an association, and if they are passing in a string it should be to_ied                        
      if self.belong_to_ids.include? key and not( value.nil? or ( value.respond_to? :empty? and value.empty? ) )
        return value.to_i
      end
      value
    end
    
    #TODO Consolidate this with call_setter
    #Called by overriden load
    def call_attribute_setter( key, value )
      #TODO If there is a setter, we shouldn't directly set the attribute hash - we should rely on the setter method
      # => Now, we are doing both
      setter_method_name = "#{key}="
      self.send( setter_method_name, @attributes[key.to_s] ) if self.respond_to? setter_method_name
    end    
    
    def attribute_getter?(method)
      columns.include?(method.to_sym)
    end

    def attribute_setter?(method)
      columns.include?(method.to_s.gsub(/=$/, '').to_sym)
    end
      

  
    # add dynamic finders.
    # This allows:
    #  User.find_all_by_email('joe@bloggs.com')
    #   => returns all users with the matching parameter
    #  User.find_by(:email, 'joe@bloggs.com')
    #   => returns the first matching user
    #  User.find_last_by(:email, 'joe@bloggs.com')
    #   => same as above, but returns the last one. (note - because we don't
    #   "sort" yet - this will fetch all of them and then return the last in
    #   the array.
    FINDER_REGEXP = /^find_(all_by|last_by|by)_([_a-zA-Z]\w*)$/

    def self.method_missing( symbol, *args )
      if symbol.to_s =~ FINDER_REGEXP 
        finder_text, field_name = symbol.to_s.scan(FINDER_REGEXP).first #The ^ and $ mean only one thing will ever match this expression so use the first
        scope = :first # matches when 'find_by' or 'find_first_by'
        case finder_text 
        when 'last_by' 
          scope = :last
        when 'all_by' 
          scope = :all
        end
        find( scope, :params => { field_name => args } )        
      else
        super( symbol, args )
      end
    end
   
    # convenience methods as per ActiveRecord
    def self.first(args = {})
      self.find(:first, args)
    end

    def self.last(args = {})
      self.find(:last, args)
    end

    def self.all(args = {})
      self.find(:all, args)
    end


    # Counts the number of items in your API that match the given
    # conditions. 
    #
    # If you pass in nothing, it will try the +default_counter_path+
    # 
    # If your API does not use the +default counter_path+, you can override it in one of two ways:
    #
    # If the path is the same for every model, you can pass the string-path to
    # self.counter_path= in your model class. This can be done for each individual
    # model.
    # Alternatively, you can pass in the counter_path for any specific instance of
    # count by passing it as an arg thus:
    # Widget.count(:counter_path => '/my_app/my_widgets_count.xml')
    # 
    # Both of these will still allow you to pass finder-args to the count method eg:.
    # Widget.count(:counter_path => '/my_app/my_widgets_count.xml', :name => 'wodget')
    # 
    # ...if all else fails (ie it tires and gets a ResourceNotFound error) -
    # the code will do a full fetch and count on a local array. If you know
    # there's no counter-action in your remote API, you're probably better
    # off doing that in your own code.
    #
    # Note: the finder here works because ActiveResource doesn't actually
    # know about how to instantiate resources properly - it will just create
    # a model that has a field called "count" on it.
    # Because we never try to save this fake resource - it should not fall
    # foul of validation...
    def self.count(args = {})
      begin
        # try the neato way assuming a "count_widgets" collection path
        # has been passed in
        try_path = self.counter_path
        # passed-in path always overrides the default
        if (args.has_key?(:counter_path) && !args[:counter_path].blank?)
          try_path = args[:counter_path] 
          args.delete(:counter_path)
        end
        if !try_path.blank?
          self.find(:one, args.merge(:from => try_path)).count
        else
          # try the default counter path.
            self.find(:one, :from => self.default_counter_path(args)).count
        end
      rescue ActiveResource::ResourceNotFound
        # if it all goes horribly, horribly wrong - fall back on the long way
        self.find(:all, args).length
      end
    end

    # an accessor that stores the model-specific path to use for counting
    # an object - in case it differs from the default (see
    # +default_counter_path)
    def self.counter_path(args = nil)
      @counter_path
    end
    def self.counter_path=(path)
      # clean up if somebody forgets to prepend a slash
      path = '/' + path unless path.blank? || path[0] == '/'
      @counter_path = path
    end
    # default counter-path to be used if counter_path is not set.
    # so: default_counter_path(args)
    # is expected to generate something equivalent to:
    #   /#{collection_path}/count.xml#{query_string(args)}
    # It uses the extended +collection_path+ with suffix_options of ['count']
    def self.default_counter_path(args)
      self.collection_path(args, nil, ['/count'])
    end

    # extend collection_path to allow suffix options - which allow us to
    # actually construct standard rails named routes
    # Pass in suffix options as an array and they will be added just after
    # the collection-path name joined with '/',  and the format will be
    # applied to the last one. Params should work as previously
    # eg:
    # User.collection_path(nil, nil, ['count'])
    # => '/users/count.xml'
    # User.collection_path(nil, {:name => 'joe'}, ['count'])
    # => '/users/count.xml?name=joe'
    # User.collection_path({:group_id => 42}, {:name => 'joe'}, ['count', 'all'])
    # => '/groups/42/users/count/all.xml?name=joe'
    def self.collection_path(prefix_options = {}, query_options = nil, suffix_options = [])
      # only override it if we pass in something different
      return super(prefix_options, query_options) if suffix_options.blank?

      prefix_options, query_options = split_options(prefix_options) if query_options.nil?
      "#{prefix(prefix_options)}#{collection_name}#{suffix_options.join('/')}.#{format.extension}#{query_string(query_options)}"
    end

    
end
