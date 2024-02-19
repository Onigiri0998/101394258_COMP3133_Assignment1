const express = require('express');
const { ApolloServer, gql, AuthenticationError, UserInputError } = require('apollo-server-express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// MongoDB models
const User = require('./models/User');
const Employee = require('./models/Employee');

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/Comp3133_assignment1')
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error(err));

const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    password: String!
    token: String
  }

  type Employee {
    id: ID!
    first_name: String!
    last_name: String!
    email: String!
    gender: String!
    salary: Float!
  }

  type Query {
    getAllEmployees: [Employee]
    getEmployeeById(id: ID!): Employee
  }

  type Mutation {
    signup(username: String!, email: String!, password: String!): User
    addEmployee(first_name: String!, last_name: String!, email: String!, gender: String!, salary: Float!): Employee
    updateEmployee(id: ID!, first_name: String, last_name: String, email: String, gender: String, salary: Float): Employee
    deleteEmployee(id: ID!): String
  }
`;

// Authentication check function
function checkAuth(context) {
  const authHeader = context.req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split('Bearer ')[1];
    if (token) {
      try {
        return jwt.verify(token, process.env.JWT_SECRET);
      } catch (err) {
        throw new AuthenticationError('Invalid/Expired token');
      }
    }
    throw new Error('Authentication token must be \'Bearer [token]\'');
  }
  throw new Error('Authorization header must be provided');
}

// Resolvers
const resolvers = {
  Query: {
    getAllEmployees: async () => await Employee.find({}),
    getEmployeeById: async (_, { id }) => await Employee.findById(id),
  },
  Mutation: {
    signup: async (_, { username, email, password }) => {
      if (email.trim() === '' || password.trim() === '' || username.trim() === '') {
        throw new UserInputError('Username, email, and password must not be empty');
      }
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        throw new UserInputError('A user with this email already exists');
      }
      const hashedPassword = await bcrypt.hash(password, 12);
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
      });
      const res = await newUser.save();

      const token = jwt.sign(
        { userId: res.id, email: res.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      return {
        ...res._doc,
        id: res._id,
        token,
      };
    },
    addEmployee: async (_, { first_name, last_name, email, gender, salary }, context) => {
      const user = checkAuth(context);
      const newEmployee = new Employee({ first_name, last_name, email, gender, salary });
      return await newEmployee.save();
    },
    updateEmployee: async (_, { id, first_name, last_name, email, gender, salary }, context) => {
      const user = checkAuth(context);
      const updatedEmployee = await Employee.findByIdAndUpdate(
        id,
        { $set: { first_name, last_name, email, gender, salary } },
        { new: true, runValidators: true }
      );
      if (!updatedEmployee) {
        throw new Error('Employee not found');
      }
      return updatedEmployee;
    },
    deleteEmployee: async (_, { id }, context) => {
      const user = checkAuth(context);
      const deletedEmployee = await Employee.findByIdAndDelete(id);
      if (!deletedEmployee) {
        throw new Error('Employee not found');
      }
      return 'Employee deleted successfully';
    },
  },
};

// Initialize Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => ({ req }),
});

const app = express();

// Apply Apollo GraphQL middleware and set the path to /graphql
server.start().then(() => {
  server.applyMiddleware({ app, path: '/graphql' });

  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () =>
    console.log(`🚀 Server ready at http://localhost:${PORT}${server.graphqlPath}`)
  );
});
