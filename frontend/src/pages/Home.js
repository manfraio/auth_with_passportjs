import React, { useEffect, useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'

const Home = () => {
    const [message, setMessage] = useState('')
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const navigate = useNavigate()

    const fetchProtectedRoute = async () => {
        try {
            const response = await axios.get('http://localhost:3000/me', { withCredentials: true })
            setMessage(`Welcome, ${response.data.name}`)
            setIsAuthenticated(true)
        } catch (error) {
            const errorMessage = error.response?.data?.error || 'Something went wrong'
            setMessage(errorMessage)
            setIsAuthenticated(false)
        }
    }

    const handleLogout = async () => {
        try {
            await axios.get('http://localhost:3000/logout', { withCredentials: true })
            setIsAuthenticated(false)
            navigate('/login')
        } catch (error) {
            const errorMessage = error.response?.data?.error || 'Something went wrong'
            setMessage(errorMessage)
        }
    }

    useEffect(() => {
        fetchProtectedRoute()
    }, [])

    return (
        <div>
            <h1>Home</h1>

            <p>{message}</p>
            
            {isAuthenticated && <button onClick={handleLogout}>Logout</button>}
        </div>
    )
}

export default Home
