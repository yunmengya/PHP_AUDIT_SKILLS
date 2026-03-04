# TP

class Array
    def custom_method
      "Overridden method"
    end
  end
  
  module Math
    def self.custom_method
      "Custom method"
    end
  end
  
  class String
    def to_s
      "Custom String representation"
    end
  end
  
  
  # FP
  
  class CustomClass
    def new_method
      "Custom logic"
    end
  end
  
  module CustomModule
    def new_method
      "Module logic"
    end
  end
  
  def custom_method
    "This is a custom method"
  end
  