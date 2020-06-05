When(/^I retrieve an API key using conjurctl$/) do
  command = 'conjurctl role retrieve-key cucumber:user:admin'
  @conjurctl_output = `#{command}`
end

Then(/^the API key is correct$/) do
  expect(@conjurctl_output).to eq("#{Credentials['cucumber:user:admin'].api_key}\n")
end
