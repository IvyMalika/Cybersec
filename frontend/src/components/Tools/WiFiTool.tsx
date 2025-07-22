import React, { useState } from 'react';
import {
  Box, Typography, Button, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, CircularProgress, Alert, TextField, InputLabel, MenuItem, Select, FormControl
} from '@mui/material';
import { useForm, Controller } from 'react-hook-form';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import axios from 'axios';

interface WiFiNetwork {
  ssid: string;
  signal: string;
  security: string;
}

interface CrackResult {
  success: boolean;
  password: string | null;
  output: string;
  error?: string;
}

const WiFiTool: React.FC = () => {
  const [networks, setNetworks] = useState<WiFiNetwork[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [crackResult, setCrackResult] = useState<CrackResult | null>(null);
  const [crackLoading, setCrackLoading] = useState(false);
  const [crackError, setCrackError] = useState<string | null>(null);

  const { control, handleSubmit, reset, watch } = useForm({
    defaultValues: {
      ssid: '',
      handshake: null,
      wordlist: null,
      bssid: '',
    },
  });

  const selectedSSID = watch('ssid');

  const handleScan = async () => {
    setLoading(true);
    setScanError(null);
    setNetworks([]);
    try {
      const res = await axios.post('/api/tools/wifi/scan', {}, { withCredentials: true });
      setNetworks(res.data.networks || []);
    } catch (err: any) {
      setScanError(err.response?.data?.error || 'WiFi scan failed');
    } finally {
      setLoading(false);
    }
  };

  const onSubmit = async (data: any) => {
    setCrackLoading(true);
    setCrackError(null);
    setCrackResult(null);
    const formData = new FormData();
    formData.append('handshake', data.handshake[0]);
    formData.append('wordlist', data.wordlist[0]);
    if (data.bssid) formData.append('bssid', data.bssid);
    try {
      const res = await axios.post('/api/tools/wifi/crack', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        withCredentials: true,
      });
      setCrackResult(res.data);
    } catch (err: any) {
      setCrackError(err.response?.data?.error || 'WiFi crack failed');
    } finally {
      setCrackLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', p: 2 }}>
      <Typography variant="h4" sx={{ mb: 2, fontWeight: 600 }}>
        WiFi Network Scanner & Cracker
      </Typography>
      <Button variant="contained" onClick={handleScan} disabled={loading} startIcon={<CloudUploadIcon />}>
        {loading ? 'Scanning...' : 'Scan for WiFi Networks'}
      </Button>
      {scanError && <Alert severity="error" sx={{ mt: 2 }}>{scanError}</Alert>}
      {networks.length > 0 && (
        <TableContainer component={Paper} sx={{ mt: 3 }}>
          <Table size="small" aria-label="wifi networks">
            <TableHead>
              <TableRow>
                <TableCell>SSID</TableCell>
                <TableCell>Signal</TableCell>
                <TableCell>Security</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {networks.map((net, idx) => (
                <TableRow key={idx} hover selected={selectedSSID === net.ssid}>
                  <TableCell>{net.ssid || <i>Hidden</i>}</TableCell>
                  <TableCell>{net.signal}</TableCell>
                  <TableCell>{net.security}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Box component="form" onSubmit={handleSubmit(onSubmit)} sx={{ mt: 4 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Crack WiFi Password
        </Typography>
        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel id="ssid-label">SSID</InputLabel>
          <Controller
            name="ssid"
            control={control}
            render={({ field }) => (
              <Select
                {...field}
                labelId="ssid-label"
                label="SSID"
                value={field.value}
                onChange={field.onChange}
              >
                {networks.map((net, idx) => (
                  <MenuItem key={idx} value={net.ssid}>{net.ssid || <i>Hidden</i>}</MenuItem>
                ))}
              </Select>
            )}
          />
        </FormControl>
        <Controller
          name="bssid"
          control={control}
          render={({ field }) => (
            <TextField {...field} label="BSSID (optional)" fullWidth sx={{ mb: 2 }} />
          )}
        />
        <Controller
          name="handshake"
          control={control}
          rules={{ required: 'Handshake file is required' }}
          render={({ field }) => (
            <Button
              variant="outlined"
              component="label"
              fullWidth
              sx={{ mb: 2 }}
            >
              Upload Handshake File (.cap)
              <input
                type="file"
                accept=".cap"
                hidden
                onChange={e => field.onChange(e.target.files)}
              />
            </Button>
          )}
        />
        <Controller
          name="wordlist"
          control={control}
          rules={{ required: 'Wordlist file is required' }}
          render={({ field }) => (
            <Button
              variant="outlined"
              component="label"
              fullWidth
              sx={{ mb: 2 }}
            >
              Upload Wordlist File (.txt)
              <input
                type="file"
                accept=".txt"
                hidden
                onChange={e => field.onChange(e.target.files)}
              />
            </Button>
          )}
        />
        <Button type="submit" variant="contained" color="primary" fullWidth disabled={crackLoading}>
          {crackLoading ? <CircularProgress size={24} /> : 'Crack Password'}
        </Button>
        {crackError && <Alert severity="error" sx={{ mt: 2 }}>{crackError}</Alert>}
        {crackResult && (
          <Alert severity={crackResult.success ? 'success' : 'warning'} sx={{ mt: 2 }}>
            {crackResult.success
              ? `Password found: ${crackResult.password}`
              : crackResult.error || 'Password not found.'}
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                {crackResult.output}
              </Typography>
            </Box>
          </Alert>
        )}
      </Box>
    </Box>
  );
};

export default WiFiTool; 