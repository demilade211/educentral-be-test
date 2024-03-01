import sendEmail from "./sendEmail";
import fs from "fs"

function wrapUrls(str) {
  // Use a regular expression to match URLs
  const urlRegex = /https?:\/\/[^\s]+/g;

  // Use another regular expression to match @-mentions
  const mentionRegex = /@[^\s]+/g;

  // Replace all URLs and @-mentions with wrapped versions
  return str.replace(urlRegex, url => `<a href="${url}">${url}</a>`)
    .replace(mentionRegex, mention => `<a href="${mention}">${mention}</a>`);
}

function wrapInAnchorTag(str) {
  // Use a regular expression to check for strings that start with @ or are web URLs
  const pattern = /@[a-zA-Z0-9._-]+|https?:\/\/[a-zA-Z0-9._-]+/gi;

  // Replace any matches with the same string wrapped in an anchor tag
  return str.replace(pattern, (match) => `<a href="${match}">${match}</a>`);
}

function wrapCharacter(str, url) {
  let result = '';
  for (const char of str) {
    if (char.startsWith('@')) {
      result += '<a href="' + url + '/' + char.slice(1) + '">' + char + '</a>';
    } else {
      result += char;
    }
  }
  return result;
}

function wrapUrlsAndUsernames(str, url) {
  // Use a regular expression to find @username and url patterns in the string
  let regex = /(?:(?:https?|ftp):\/\/|\b(?:[a-z\d]+\.))(?:(?:[^\s()<>]+|\((?:[^\s()<>]+|(?:\([^\s()<>]+\)))?\))+(?:\((?:[^\s()<>]+|(?:\(?:[^\s()<>]+\)))?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))?/gi;
  let matches = str.match(regex);

  // If there are no matches, return the original string
  if (!matches) return str;

  // Iterate over the matches and wrap each one in an anchor tag with the specified URL
  for (let match of matches) {
    if (match[0] === "@") {
      let username = match.slice(1); // remove the "@" from the username
      str = str.replace(match, `<a href="${url}/${username}">${username}</a>`);
    } else {
      str = str.replace(match, `<a href="${match}">${match}</a>`);
    }
  }

  return str;
}

export const paginate = (items, page, perPage) => {
  return items.slice(perPage * (page - 1), perPage * page);
}

export const handleEmail = async (user, next, message,res) => {
  try {
    await sendEmail({
      email: user.email,
      subject: "Suprise Vault OTP",
      message
    })

    return res.status(200).json({
      success: true,
      message: `Email sent to ${user.email}`
    })

  } catch (error) {
    user.otp = undefined;
    user.expiretoken = undefined;

    await user.save({ validateBeforeSave: false })
    return res.send(error.message, 500)
  }
}
