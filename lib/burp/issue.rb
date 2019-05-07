module Burp
  # We use this string to replace invalid UTF-8 bytes with.
  INVALID_UTF_REPLACE = '<?>'

  class Issue

    # This allows external callers (and specs) to check for implemented
    # properties
    def respond_to?(method, include_private=false)
      return true if supported_tags.include?(method.to_sym)
      super
    end

    private

    def cleanup_html(source)
      result = source.dup
      result.gsub!(/&quot;/, '"')
      result.gsub!(/&amp;/, '&')
      result.gsub!(/&lt;/, '<')
      result.gsub!(/&gt;/, '>')
      result.gsub!(/&nbsp;/, ' ')

      result.gsub!(/<span.*?>/, '')
      result.gsub!(/<\/span>/, '')
      
      result.gsub!(/<b>(.*?)<\/b>/, '*\1*')
      result.gsub!(/<br>|<\/br>/){"\n"}
      result.gsub!(/<font.*?>(.*?)<\/font>/m, '\1')
      result.gsub!(/<h\d?>(.*?)<\/h\d?>/, '*\1*')
      result.gsub!(/<i>(.*?)<\/i>/, '\1')
      result.gsub!(/<p>|<\/p>/){"\n"}
      result.gsub!(/<pre.*?>(.*?)<\/pre>/m){|m| "\n\nbc.. #{ $1 }\n\np.  \n" }

      result.gsub!(/<ul>(.*?)<\/ul>/m){|m| "#{ $1 }\n"}
      result.gsub!(/<li>(.*?)<\/li>/m){|m| "\n* #{ $1 }"}
      result.gsub!(/<a href=\"(.*?)\">(.*?)<\/a>/i) { "\"#{$2.strip}\":#{$1.strip}" }

      result.gsub!(/<table>(.*?)<\/table>/m){|m| "\n\n#{ $1 }\n\n" }
      result.gsub!(/<tr>(.*?)<\/tr>/m){|m| "|#{ $1 }\n" }
      result.gsub!(/<td>(.*?)<\/td>/, '\1|')

      result
    end
  end
end
