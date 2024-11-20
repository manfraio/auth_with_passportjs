import React, { useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'

const Login = () => {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const navigate = useNavigate()

    const handleLogin = async (e) => {
        e.preventDefault()

        try {
            const response = await axios.post('http://localhost:3000/login', { email, password }, { withCredentials: true })
            alert(`Login successful! Welcome, ${response.data.name}`)
            navigate('/') 
        } catch (error) {
            const errorMessage = error.response?.data?.error || 'Login failed'
            alert(errorMessage)
        }
    }

    return (
        <div>
            <h1>Login</h1>

            <form onSubmit={handleLogin}>
                <input type="text" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required />
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" required />
                <button type="submit">Login</button>
            </form>

            <br/>
            <a href="http://localhost:3000/auth/google">Login with Google</a>
        </div>

    )
}

export default Login
