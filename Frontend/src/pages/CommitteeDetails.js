import React from 'react';
import { useParams } from 'react-router-dom';
import { Container, Typography } from '@mui/material';
import CommitteeMessages from '../components/CommitteeMessages';

const CommitteeDetails = () => {
  const { id } = useParams(); // Committee ID

  return (
    <Container maxWidth="lg" sx={{ mt: 4 }}>
      {/* Existing committee details */}
      <Typography variant="h4" gutterBottom>
        Committee Details
      </Typography>
      {/* Other committee information */}

      {/* Messaging Section */}
      <CommitteeMessages />
    </Container>
  );
};

export default CommitteeDetails;
