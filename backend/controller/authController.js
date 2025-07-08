import { OAuth2Client } from 'google-auth-library';
import { User } from '../model/user.models.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID); // from your .env

export const googleLogin = asyncHandler(async (req, res) => {
  console.log('Google login endpoint hit');
  const { token } = req.query; // Use query parameter to get the token
    //  console.log('Received token:', token);
  if (!token) {
    return res.status(400).json({
      success: false,
      message: 'ID token is required',
    });
  }

  // Verify the ID token
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  const { email, name, picture } = payload;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Email not found in token payload',
    });
  }

  // Check if user exists or create a new one
  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({ name, email, picture });
  }

  // Generate app-specific tokens
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  const loggedInUser = await User.findById(user._id).select('-password -refreshToken');

  return res.status(200).json(
      new ApiResponse(200, {
        user: loggedInUser,
        accessToken,
        refreshToken,
      }, 'User logged in successfully')
    );
});
