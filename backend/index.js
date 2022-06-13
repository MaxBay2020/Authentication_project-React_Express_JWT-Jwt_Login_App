import express from 'express'
// 如果不实用body-parser包，那么我们使用req.body时就获取不到前端传来的数据
import bodyParser from 'body-parser'
const app = express()

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
// parse application/json
app.use(bodyParser.json())

// 因为前端地址和后端api地址不同，因此需要使用到cors
import cors from 'cors'
app.use(cors())

// 需要使用到.env文件
import dotenv from 'dotenv'
dotenv.config()

// 引包
import jwt from 'jsonwebtoken'

// 使用假数据，模拟从数据库来的数据
const users = [
    {
        id: "1",
        username: "john",
        password: "John0908",
        isAdmin: true,
    },
    {
        id: "2",
        username: "jane",
        password: "Jane0908",
        isAdmin: false,
    },
]

// 注意！！！access token和refresh token的发放是在用户登录成功时发放的！！！
// 登录的api
app.post('/api/login', (req,res) => {
    const {username, password} = req.body
    // 查看该用户是否已经注册且密码匹配
    const user = users.find(user => user.username === username && user.password === password)

    if(user){
        // 如果有该用户且密码正确，则返回这个用户到前端
        // res.json(user)

        // 如果有该用户且密码正确，则生成access token和refresh token
        // 注意！生成access token和refresh token使用的secret key不一样
        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)

        refreshTokens.push(refreshToken)


        // 最后发送到前端的数据中，需要将生成的token也返回回去
        res.json({
            username:user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    }
    else
        // 如果用户不存在或密码错误
        res.status(400).json('Username or password incorrect!')
})

// 这个方法用来发放access token
const generateAccessToken=(user) => {
    // 使用sign()方法，这个方法需要传三个参数：
    // 第一个参数：传一个对象进去，对象可以自定义，这里的jwt是根据id和isAdmin这两个字段来生成token的
    // 第二个参数：是一个自定义的secret key，需要放在.env文件中
    // 第三个参数：可以设定我们的这个token多久过期
    return jwt.sign(
        {
            id: user.id,
            isAdmin:user.isAdmin
        }
        ,
        process.env.JWT_ACCESS_TOKEN_SECREAT_KEY,
        {
            expiresIn: '15m', // 15分钟，token会自动过期
        })
}

// 这个方法用来发放refresh token
const generateRefreshToken=(user) => {
    // 还是使用sign()方法发放refresh token，但是不设置过期时间，而且secret key和access token不一样
    return jwt.sign(
        {
            id: user.id,
            isAdmin:user.isAdmin
        }
        ,
        process.env.JWT_REFRESH_TOKEN_SECREAT_KEY)
}


// 注意！！！jwt的验证时在中间键里验证的！！！
// 创建一个中间键，用来判断前端做请求时，header上的token是否存在并有效
const verify = (req,res,next)=>{
    // 如果我们在前端做请求时，将token放进header中，在后端就可以通过req.headers.authorization获取到这个token了
    // 注意！此时的authHeader是带有Bearer 前缀的！需要进行字符串切割，来取得token
    const authHeader = req.headers.authorization

    if(authHeader){
        // 如果token存在，说明用户登录了
        // 因为发来的token是带有Bearer 前缀的，因此要进行字符串切割
        const token = authHeader.split(' ')[1]

        // 使用verify（）方法，对前端发来的token进行验证，需要传3哥参数：
        // 第一个参数：从前端Header中读取到的token
        // 第二个参数：在生成jwt时使用的secret key，必须和生成时的secret key一样，可以认为这个是解码关键词
        // 第三个参数：回调函数，需要一个err对象和解码出来的user，如果从前端header传过来的token正确，那么user就是创建token时，传进去的那个对象；
        jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECREAT_KEY, (err, user) => {
            if(err)
                // 如果token存在，但token无效
                res.status(403).json('Token is not valid')

            // 如果token存在且有效，则赋值到req.user上，并传到下一个中间键
            req.user = user
            next()
        })

    }else{
        // 如果前端做的请求，header中的token不存在，则说明用户没有登录
        res.status(401).json('Your are not authenticated!')
    }
}

// 模拟refresh token，正常开发应该存在redis中
let refreshTokens = []

// 这个路由使用了verify()这个中间键，意思是：只有携带正确token的前端请求才能进入
app.delete('/api/users/:userId', verify, (req,res) => {
    // 进来之后，我们就可以进行正常判断了
    if(req.user.id === req.params.userId || req.user.isAdmin)
        res.status(200).json('User has been deleted!')
    else
        res.status(403).json('You are not allowed to delete this user!')
})


// 这个路由用来在access token过期后，重新发放access token和refresh token
app.post('/api/refresh', (req,res) => {
    // 前端需要将refresh token发送到这个路由中
    const refreshToken = req.body.token

    // 如果没有refresh token
    if(!refreshToken)   res.status(401).json('You are not authenticated!')

    // 如果redis中没有发过来的这个refresh token
    if(!refreshTokens.includes(refreshToken))
        res.status(403).json('Refresh token is not valid!')

    // 如果有refresh token，则进行有效性验证
    jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECREAT_KEY, (err, user) => {
        if(err)
            // 如果refresh token是无效的
            console.log(err)
        else{
            // 如果refresh token是有效的，则清空redis，重新发放access token和refresh token
            refreshTokens = refreshTokens.filter(token => token !== refreshToken)
            const newAccessToken = generateAccessToken(user)
            const newRefreshToken = generateRefreshToken(user)
            refreshTokens.push(newRefreshToken)

            // 将新的access token和refresh token发送回前端
            res.status(200).json({
                accessToken: newAccessToken,
                refreshToken: newRefreshToken
            })
        }

    })
})

// logout 用户的路由
// 因为只有登录了的用户才可以logout，因此需要添加中间键verify！
// 注意！这里是清空了redis中的refresh token，因为如果我们只是删除了access token，那黑客可能
// 使用refresh token来获得新的access token和refresh token
// 因此，需要直接清空refresh token
app.post('/api/logout', verify, (req,res) => {
    // 模拟从redis中删除refresh token
    const refreshToken = req.body.token

    refreshTokens = refreshTokens.filter(token => token !== refreshToken)
    res.status(200).json('You logged out successfully!')
})

app.listen(5000, () => {
    console.log('Server is running at port 5000!')
})
