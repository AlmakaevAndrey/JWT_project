import { useState } from 'react';
import './App.css';
import { api } from './axios';
import type { AxiosError } from 'axios';

function App() {
  const [token, setToken] = useState<string>("");
  const [message, setMessage] = useState("");

  const login = async () => {
    try {
      const res = await api.post("/login", {
        username: "admin",
        password: "1234",
      }, { withCredentials: true });

      setToken(res.data.accessToken);
    } catch (error) {
      console.error("Login error", error)
      alert("Login failed");
    }
  };

  const getProtected = async () => {
    try {
      const res = await api.get("/protected", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        withCredentials: true,
      });
      setMessage(res.data.message);
    } catch (error) {
      const err = error as AxiosError;

      if (err.response?.status === 403) {
        try {
          const refresh = await api.post('/refresh', {}, { withCredentials: true });
          const newAccessToken = refresh.data.accessToken;
          setToken(newAccessToken);
          
          const retryRes = await api.get("protected", {
            headers: {Authorization: `Bearer ${newAccessToken}`},
            withCredentials: true,
          })
          setMessage(retryRes.data.message)
        } catch (error) {
          console.error("Session error", error)
          alert("Session expired");
        }
      } else {
        alert("Unauthorized");
      }
    }
  };

  const logout = async () => {
    await api.post('/logout', {}, { withCredentials: true });
    setToken("");
    setMessage("");
  };

  return (
    <div className="container">
      <h1>JWT Auth</h1>
      <button onClick={login}>Login</button>
      <button onClick={getProtected}>Access Protected</button>
      <button onClick={logout}>Logout</button>
      <p>{message}</p>
    </div>
  );
}

export default App;
