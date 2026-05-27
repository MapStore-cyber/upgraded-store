import { useState } from 'react'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full">
        <h1 className="text-3xl font-bold text-gray-800 mb-2 text-center">
          MapStore Marketplace
        </h1>
        <p className="text-gray-600 text-center mb-8">
          Welcome to your application
        </p>
        
        <div className="bg-indigo-50 rounded-lg p-6 mb-6">
          <p className="text-center text-gray-700 mb-4">
            Count: <span className="text-2xl font-bold text-indigo-600">{count}</span>
          </p>
          <button
            onClick={() => setCount(count + 1)}
            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded-lg transition duration-200"
          >
            Increment
          </button>
        </div>

        <button
          onClick={() => setCount(0)}
          className="w-full bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded-lg transition duration-200"
        >
          Reset
        </button>
      </div>
    </div>
  )
}

export default App
