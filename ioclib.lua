#!lua name=ioclib

local function has_value (table, val)
    for index, value in ipairs(table) do
        if value == val then
            return true
        end
    end

    return false
end

local function get_by_value(keys, args)
    local search_query = args[1]
    if string.len(search_query) <= 3 then
        return {}
    end
    local last_ioc_id = redis.call('GET', 'ioc:id')
    local searched_indexes = {}


    for i = 1, last_ioc_id do
        local ioc_value = redis.call('HGET', 'ioc:id:' .. i, 'ioc')
        if string.find(ioc_value, search_query) ~= nil then
            table.insert(searched_indexes, i)
        end
    end

    if (#searched_indexes == 0) then
        return {}
    end

    local result = {}
    for i = 1, #searched_indexes do
        table.insert(result, redis.call('HGETALL', 'ioc:id:' .. searched_indexes[i]))
    end

    return result
end

local function get_all_iocs()
    local last_ioc_id = redis.call('GET', 'ioc:id')
    local all_iocs = {}
    for i = 1, last_ioc_id do
        all_iocs[i]=redis.call('HGETALL', 'ioc:id:' .. i)
    end
    return all_iocs
end

local function get_by_type(keys, args)
    local available_types = {'Email', 'URL', 'IP', 'Host', 'Filepath', 'Filename', 'Registry', 'MD5', 'SHA1', 'SHA256', 'CVE'}
    local ioc_type = args[1]
    if not has_value(available_types, ioc_type)  then
        return redis.error_reply('IOC type is only: ' .. table.concat(available_types, ', '))
    end

    local filtered_iocs = {}
    local cursor = '0'

    repeat
        local result = redis.call('SSCAN', 'ioc:types:' .. ioc_type, cursor)
        cursor = result[1]

        for _,value in ipairs(result[2]) do
            table.insert(filtered_iocs, redis.call('HGETALL', 'ioc:id:' .. value))
        end


    until cursor == '0'

    return filtered_iocs
end


local function get_by_types()
    local last_ioc_id = redis.call('GET', 'ioc:id')
    local all_types = {}


    for i = 1, last_ioc_id do
        local ioc_data = redis.call('HGET', 'ioc:id:' .. i, 'type')
        if all_types[ioc_data] == nil then
            all_types[ioc_data] = 1
        else
            all_types[ioc_data] = all_types[ioc_data] + 1
        end
    end

    local result = {}
    local keys = {}
    for k in pairs(all_types) do
        table.insert(keys, k)
    end

    for i = 1, #keys do
        local k, v = keys[i], all_types[keys[i]]
        table.insert(result, k)
        table.insert(result, v)
    end

    return result
end


local function get_by_years()
    local cursor = '0'
    local articles_per_year = {}
    local result_table = {}

    repeat
        local result = redis.call('SSCAN', 'articles', cursor)
        cursor = result[1]

        for _,value in ipairs(result[2]) do
            local article_info = redis.call('HMGET', 'articles:' .. value, 'year', 'ioc_count')
            if articles_per_year[article_info[1]] == nil then
                articles_per_year[article_info[1]] = tonumber(article_info[2])
            else
                articles_per_year[article_info[1]] = articles_per_year[article_info[1]] + tonumber(article_info[2])
            end
        end

    until cursor == '0'
    

    local ordered_years = {}
    for k in pairs(articles_per_year) do
        table.insert(ordered_years, k)
    end

    table.sort(ordered_years)
    for i = 1, #ordered_years do
        local k, v = ordered_years[i], articles_per_year[ordered_years[i]]
        table.insert(result_table, k)
        table.insert(result_table, tostring(v))
    end

    return result_table
end


local function get_by_year(keys, args)
    local year = args[1]
    local monts_numbers = {'01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'}
    local iocs_per_month = {}

    for i = 1, #monts_numbers do
        table.insert(iocs_per_month, redis.call('SCARD', 'ioc:dates:' .. monts_numbers[i] .. ':' .. year))
    end

    return iocs_per_month
end


local function get_by_month(keys, args)
    local month = args[1]
    local year = args[2]
    local monts_numbers = {'01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'}

    if not has_value(monts_numbers, month)  then
        return redis.error_reply('Month is only: ' .. table.concat(monts_numbers, ', '))
    end

    local filtered_iocs = {}
    local cursor = '0'

    repeat
        local result = redis.call('SSCAN', 'ioc:dates:' .. month .. ':' .. year, cursor)
        cursor = result[1]

        for _,value in ipairs(result[2]) do
            table.insert(filtered_iocs, redis.call('HGETALL', 'ioc:id:' .. value))
        end


    until cursor == '0'

    return filtered_iocs
end

redis.register_function('get_all_iocs', get_all_iocs)
redis.register_function('get_by_value', get_by_value)
redis.register_function('get_by_type', get_by_type)
redis.register_function('get_by_types', get_by_types)
redis.register_function('get_by_year', get_by_year)
redis.register_function('get_by_years', get_by_years)
redis.register_function('get_by_month', get_by_month)