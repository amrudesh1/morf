import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Upload, FileSearch, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-react';
import { useDropzone } from 'react-dropzone';

type Screen = 'splash' | 'upload' | 'processing' | 'results';

interface Secret {
  type: string;
  value: string;
  severity: 'high' | 'medium' | 'low';
}

function App() {
  const [currentScreen, setCurrentScreen] = useState<Screen>('splash');
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [file, setFile] = useState<File | null>(null);

  useEffect(() => {
    // Simulate splash screen duration
    const timer = setTimeout(() => {
      setCurrentScreen('upload');
    }, 2000);

    return () => clearTimeout(timer);
  }, []);

  const onDrop = (acceptedFiles: File[]) => {
    setFile(acceptedFiles[0]);
    setCurrentScreen('processing');
    
    // Simulate processing
    setTimeout(() => {
      // Mock secrets discovery
      setSecrets([
        { type: 'API Key', value: 'ak_*****', severity: 'high' },
        { type: 'Database URL', value: 'mongodb://*****', severity: 'high' },
        { type: 'AWS Secret', value: 'aws_*****', severity: 'medium' },
        { type: 'Firebase Config', value: 'firebase_*****', severity: 'low' },
      ]);
      setCurrentScreen('results');
    }, 3000);
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/vnd.android.package-archive': ['.apk']
    }
  });

  const screens = {
    splash: (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="flex flex-col items-center justify-center h-screen bg-gradient-to-br from-blue-900 to-black"
      >
        <motion.div
          animate={{ scale: [1, 1.2, 1] }}
          transition={{ repeat: Infinity, duration: 2 }}
          className="text-blue-500 mb-4"
        >
          <Shield size={100} />
        </motion.div>
        <motion.h1
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="text-4xl font-bold text-white mb-2"
        >
          MORF
        </motion.h1>
        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="text-blue-200 text-center"
        >
          Mobile Reconnaissance Framework
        </motion.p>
      </motion.div>
    ),

    upload: (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        className="min-h-screen bg-gray-100 p-8"
      >
        <div className="max-w-3xl mx-auto">
          <h1 className="text-3xl font-bold text-gray-800 mb-8 flex items-center">
            <Shield className="mr-2 text-blue-600" />
            MORF Scanner
          </h1>
          
          <div
            {...getRootProps()}
            className={`
              border-4 border-dashed rounded-lg p-12 text-center cursor-pointer
              transition-colors duration-200
              ${isDragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-blue-400'}
            `}
          >
            <input {...getInputProps()} />
            <Upload className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-xl text-gray-600 mb-2">Drop your APK file here</p>
            <p className="text-sm text-gray-500">or click to select file</p>
          </div>
        </div>
      </motion.div>
    ),

    processing: (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="min-h-screen bg-gray-100 flex items-center justify-center"
      >
        <div className="text-center">
          <motion.div
            animate={{ 
              rotate: 360,
              scale: [1, 1.2, 1]
            }}
            transition={{ 
              rotate: { duration: 2, repeat: Infinity, ease: "linear" },
              scale: { duration: 1, repeat: Infinity }
            }}
            className="text-blue-600 mb-4"
          >
            <FileSearch size={64} />
          </motion.div>
          <h2 className="text-2xl font-semibold text-gray-800 mb-2">Analyzing APK</h2>
          <p className="text-gray-600">Scanning for sensitive information...</p>
        </div>
      </motion.div>
    ),

    results: (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="min-h-screen bg-gray-100 p-8"
      >
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center justify-between mb-8">
            <h1 className="text-3xl font-bold text-gray-800 flex items-center">
              <ShieldAlert className="mr-2 text-blue-600" />
              Scan Results
            </h1>
            <button
              onClick={() => {
                setFile(null);
                setSecrets([]);
                setCurrentScreen('upload');
              }}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              New Scan
            </button>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">File Information</h2>
            <p className="text-gray-600">
              Filename: {file?.name}<br />
              Size: {file?.size ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : 'Unknown'}
            </p>
          </div>

          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-xl font-semibold mb-4">Discovered Secrets</h2>
            <div className="space-y-4">
              {secrets.map((secret, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="border rounded-lg p-4"
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-semibold text-gray-800">{secret.type}</h3>
                      <p className="text-gray-600 font-mono text-sm">{secret.value}</p>
                    </div>
                    <span className={`
                      px-3 py-1 rounded-full text-sm
                      ${secret.severity === 'high' ? 'bg-red-100 text-red-800' :
                        secret.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-green-100 text-green-800'}
                    `}>
                      {secret.severity}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </motion.div>
    )
  };

  return (
    <AnimatePresence mode="wait">
      {screens[currentScreen]}
    </AnimatePresence>
  );
}

export default App;