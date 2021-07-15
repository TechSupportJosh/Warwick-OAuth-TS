# Warwick OAuth Example

I wanted to use the University of Warwick's OAuth login for some projects, however all the OAuth 1.0a libraries I tried either didn't have TypeScript support, or didn't work as expected. Therefore, I ended up using the helper library (OAuth-1.0a)[https://www.npmjs.com/package/oauth-1.0a] to handle the signing of the requests and implementing the flow myself.

If you want to give this a go, insert your consumer key/secret into the `src/warwickapi.ts` file, run `npm run dev` and then go to `http://localhost:8080`. If all is successful, you should be shown the user attributes returned from the Warwick API.

