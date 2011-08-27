# MongoSessionStore

## Description

This is a fork of the DataMapper session store, modified to work with MongoMapper and Mongoid.

## Installation

The current version is only compatible with Rails 3

    gem install mongo_session_store

However if you want to use it with Rails 2.3.x, you just have to install the latest 1.x version

    gem install mongo_session_store --version=1.1.2

## Usage with MongoMapper

In your Gemfile:

    gem "mongo_mapper-rails3", :require => "mongo_mapper"
    gem "mongo_session_store"

In the session_store initializer (config/initializers/session_store.rb):

    require "mongo_session_store/mongo_mapper"
    ActionController::Base.session_store = :mongo_mapper_store

## Usage with Mongoid

In your Gemfile:

    gem "mongoid"
    gem "mongo_session_store"

In the session_store initializer (config/initializers/session_store.rb):

    require "mongo_session_store/mongoid"
    ActionController::Base.session_store = :mongoid_store

## Contributors

* Nicolas Mérouze
* Chris Brickley
* Tony Pitale
* Nicola Racco
* Matt Powell

## License

Copyright (c) 2010 Nicolas Mérouze
Copyright (c) 2009 Chris Brickley
Copyright (c) 2009 Tony Pitale

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
