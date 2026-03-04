function main()
    local result = (function()
      return (function()
        return (function()
          return (function()
            return (function()
              return "Level 5"
            end)()
          end)()
        end)()
      end)()
    end)()
  
    print(result)
  end
  
  main()
  