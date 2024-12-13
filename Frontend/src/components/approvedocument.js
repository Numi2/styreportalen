import React, { useRef } from 'react';
import { Box, Button } from '@mui/material';
import SignatureCanvas from 'react-signature-canvas';

const SignaturePad = ({ onSave, onClear }) => {
  const sigCanvas = useRef({});

  const handleSave = () => {
    if (!sigCanvas.current.isEmpty()) {
      const dataURL = sigCanvas.current.getTrimmedCanvas().toDataURL('image/png');
      onSave(dataURL);
    }
  };

  return (
    <Box>
      <SignatureCanvas 
        ref={sigCanvas} 
        penColor="black" 
        canvasProps={{ width: 500, height: 200, className: 'sigCanvas' }} 
      />
      <Box sx={{ mt: 2 }}>
        <Button variant="outlined" onClick={() => sigCanvas.current.clear()} sx={{ mr: 2 }}>
          Clear
        </Button>
        <Button variant="contained" color="primary" onClick={handleSave}>
          Save Signature
        </Button>
      </Box>
    </Box>
  );
};

export default SignaturePad;