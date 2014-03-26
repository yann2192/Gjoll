-- gjoll configuration file

local d = gjoll.new(888, "127.0.0.1", 10000)

d:add_friend(888, "secretkey")

d:add_rule(1234, "127.0.0.1", 10001)

-- create a route to myself
d:add_route(888, 1234, "127.0.0.1", 10000, "127.0.0.1", 10002)
